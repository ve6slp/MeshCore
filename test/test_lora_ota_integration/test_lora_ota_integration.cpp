#include <gtest/gtest.h>

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <vector>

#include <Dispatcher.h>
#include <Mesh.cpp>
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

// Native does not link Identity.cpp. These packet-only tests must not invoke identity crypto.
namespace mesh {
Identity::Identity() { std::memset(pub_key, 0, sizeof(pub_key)); }
LocalIdentity::LocalIdentity() { std::memset(prv_key, 0, sizeof(prv_key)); }
bool Identity::verify(const uint8_t*, const uint8_t*, int) const {
  ADD_FAILURE() << "Unexpected non-OTA identity verification in packet-boundary test";
  return false;
}
void LocalIdentity::sign(uint8_t*, const uint8_t*, int) const {
  ADD_FAILURE() << "Unexpected non-OTA identity signing in packet-boundary test";
}
void LocalIdentity::calcSharedSecret(uint8_t*, const uint8_t*) const {
  ADD_FAILURE() << "Unexpected ECDH in packet-boundary test";
}
}

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

class PacketCaptureRadio : public FakeRadio {
public:
  std::vector<uint8_t> sent;
  bool startSendRaw(const uint8_t* data, int len) override {
    sent.assign(data, data + len);
    return FakeRadio::startSendRaw(data, len);
  }
};

class PacketBoundaryRng : public RNG {
public:
  void random(uint8_t* dest, size_t size) override { std::memset(dest, 0x36, size); }
};

class PacketBoundaryRtc : public RTCClock {
public:
  uint32_t getCurrentTime() override { return 1; }
  void setCurrentTime(uint32_t) override {}
};

class PacketBoundaryTables : public MeshTables {
public:
  bool wasSeen(const Packet*) override { return false; }
  void markSeen(const Packet*) override {}
  void clear(const Packet*) override {}
};

class ProductionPacketMesh : public Mesh {
public:
  using Mesh::onRecvPacket;
  ProductionPacketMesh(Radio& radio, MillisecondClock& clock, RNG& rng, RTCClock& rtc,
                       PacketManager& manager, MeshTables& tables)
      : Mesh(radio, clock, rng, rtc, manager, tables) {}
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
  EXPECT_EQ(144000u, integration.status(0).dutyBudgetMs);
  EXPECT_EQ(72000u, integration.status(0).dutyUsedMs);
  // The 47,987-ms estimate reserves exactly the remaining 72,000 ms at completion.
  EXPECT_TRUE(integration.canTransmit(0, OtaAirtimeCategory::Relay, 47987, true, false));
  EXPECT_FALSE(integration.canTransmit(0, OtaAirtimeCategory::Relay, 47988, true, false));
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

namespace {
struct AbortGenerationCleanupProbe {
  unsigned checks = 0, cleanups = 0;
  bool failCleanup = false;
  static mesh::ota::usb::UsbOtaResult invoke(void* ctx,
      const ::ota::storage::OtaCandidateStore::Snapshot&, bool cleanup) {
    auto& self = *static_cast<AbortGenerationCleanupProbe*>(ctx);
    if (cleanup) ++self.cleanups;
    else ++self.checks;
    return cleanup && self.failCleanup ? mesh::ota::usb::UsbOtaResult::IoError : mesh::ota::usb::UsbOtaResult::Ok;
  }
};
}

TEST(LoraOtaAbortGeneration, CapturedRfAbortCannotCancelSameImageReuploadOrReachCleanupAcrossWrap) {
  using namespace mesh::ota;
  using namespace mesh::ota::usb;
  using Store = ::ota::storage::OtaCandidateStore;
  for (const uint32_t generation : {0u, 1u, UINT32_MAX}) {
    SCOPED_TRACE(generation);
    LeanFixture fx;
    const uint8_t owner_seed[32] = {0xA1}, admin_seed[32] = {0xA2};
    ::ota::test::Ed25519TestSigner owner(owner_seed), admin(admin_seed);
    fx.admins.add(owner.publicKey()); fx.admins.add(admin.publicKey());
    uint8_t image[168] = {0x51}, canonical[59], signature[64];
    fx.buildSmallManifest(image, sizeof(image), canonical);
    owner.sign(canonical, sizeof(canonical), signature);
    auto& receiver = fx.integration.leanReceiver();
    ASSERT_EQ(UsbOtaResult::Ok, receiver.begin(owner.publicKey(), canonical, signature, false, false));
    Store::Snapshot initial;
    ASSERT_TRUE(fx.candidate_store.load(initial));
    initial.sessionId = generation;
    ASSERT_TRUE(fx.candidate_store.append(initial));
    receiver.restore();
    ASSERT_EQ(UsbOtaResult::Ok, receiver.putBlock(0, image, 84));
    const auto admitted = receiver.status();
    uint8_t message[kAbortSignedBytes], abort_signature[64], captured[kOtaAbortFrameBytes];
    buildAbortSignedMessage(fx.target_public_key, admitted.imageHash, generation, message);
    admin.sign(message, sizeof(message), abort_signature);
    ASSERT_EQ(165u, encodeOtaAbortFrame(admin.publicKey(), fx.target_public_key, admitted.imageHash,
                                       generation, abort_signature, captured, sizeof(captured)));
    AbortGenerationCleanupProbe cleanup;
    fx.integration.attachUnadmittedAbort(&cleanup, AbortGenerationCleanupProbe::invoke);
    ASSERT_TRUE(fx.integration.handleReceivedFrame(captured, sizeof(captured), 10));
    ASSERT_EQ(Store::Phase::Aborted, receiver.status().phase);
    ASSERT_EQ(generation + 1u, receiver.status().generation);
    const auto writes = fx.candidate_flash.programOpCount();
    ASSERT_TRUE(fx.integration.handleReceivedFrame(captured, sizeof(captured), 11));
    EXPECT_EQ(writes, fx.candidate_flash.programOpCount());
    uint8_t aborted_generation_frame[kOtaAbortFrameBytes];
    buildAbortSignedMessage(fx.target_public_key, admitted.imageHash, receiver.status().generation, message);
    admin.sign(message, sizeof(message), abort_signature);
    encodeOtaAbortFrame(admin.publicKey(), fx.target_public_key, admitted.imageHash,
                       receiver.status().generation, abort_signature, aborted_generation_frame,
                       sizeof(aborted_generation_frame));
    ASSERT_TRUE(fx.integration.handleReceivedFrame(aborted_generation_frame, sizeof(aborted_generation_frame), 11));
    EXPECT_EQ(writes, fx.candidate_flash.programOpCount());

    uint8_t reupload[kOtaReuploadFrameBytes] = {kOtaReuploadKind}, reupload_message[160];
    std::memcpy(reupload + 1, owner.publicKey(), 32);
    std::memcpy(reupload + 33, fx.target_public_key, 32);
    std::memcpy(reupload + 65, admitted.manifestHash, 32);
    putBE32(reupload + 97, receiver.status().generation);
    const auto signed_len = buildOtaReuploadMessage(reupload, reupload_message);
    owner.sign(reupload_message, signed_len, reupload + 101);
    ASSERT_TRUE(fx.integration.handleReceivedFrame(reupload, sizeof(reupload), 12));
    ASSERT_EQ(UsbOtaResult::Ok, receiver.putBlock(0, image, 84));
    const auto fresh = receiver.status();
    ASSERT_EQ(Store::Phase::Receiving, fresh.phase);
    ASSERT_EQ(generation + 2u, fresh.generation);
    ASSERT_EQ(1u, fresh.receivedBlocks);
    const auto checks = cleanup.checks, cleanups = cleanup.cleanups;
    const std::vector<uint8_t> journal(fx.candidate_flash.rawBuffer(),
                                      fx.candidate_flash.rawBuffer() + fx.candidate_flash.rawSize());
    const std::vector<uint8_t> staging(fx.image_flash.rawBuffer(),
                                      fx.image_flash.rawBuffer() + fx.image_flash.rawSize());
    EXPECT_FALSE(fx.integration.handleReceivedFrame(captured, sizeof(captured), 13));
    EXPECT_FALSE(fx.integration.handleReceivedFrame(aborted_generation_frame, sizeof(aborted_generation_frame), 13));
    EXPECT_EQ(UsbOtaResult::Mismatch, receiver.abort(admin.publicKey(), captured + 101,
                                                   admitted.imageHash, generation));
    EXPECT_EQ(fresh.phase, receiver.status().phase);
    EXPECT_EQ(fresh.generation, receiver.status().generation);
    EXPECT_EQ(fresh.receivedBlocks, receiver.status().receivedBlocks);
    EXPECT_TRUE(receiver.isBlockReceived(0));
    EXPECT_FALSE(receiver.isBlockReceived(1));
    EXPECT_EQ(checks, cleanup.checks); EXPECT_EQ(cleanups, cleanup.cleanups);
    EXPECT_EQ(0, std::memcmp(journal.data(), fx.candidate_flash.rawBuffer(), journal.size()));
    EXPECT_EQ(0, std::memcmp(staging.data(), fx.image_flash.rawBuffer(), staging.size()));

    buildAbortSignedMessage(fx.target_public_key, fresh.imageHash, fresh.generation, message);
    admin.sign(message, sizeof(message), abort_signature);
    EXPECT_EQ(UsbOtaResult::Ok, receiver.abort(admin.publicKey(), abort_signature, fresh.imageHash, fresh.generation));
  }
}

TEST(LoraOtaAbortGeneration, RfCodecRejectsOldAndPartialFramesAndBindsEveryAuthorityField) {
  using namespace mesh::ota;
  using namespace mesh::ota::usb;
  LeanFixture fx;
  const uint8_t owner_seed[32] = {0xA3}, outsider_seed[32] = {0xA4};
  ::ota::test::Ed25519TestSigner owner(owner_seed), outsider(outsider_seed);
  fx.admins.add(owner.publicKey());
  uint8_t image[168] = {0x52}, canonical[59], signature[64], message[kAbortSignedBytes];
  fx.buildSmallManifest(image, sizeof(image), canonical); owner.sign(canonical, sizeof(canonical), signature);
  auto& receiver = fx.integration.leanReceiver();
  ASSERT_EQ(UsbOtaResult::Ok, receiver.begin(owner.publicKey(), canonical, signature, false, false));
  const auto before = receiver.status();
  buildAbortSignedMessage(fx.target_public_key, before.imageHash, before.generation, message);
  owner.sign(message, sizeof(message), signature);
  uint8_t encoded[kOtaAbortFrameBytes + 1];
  std::memset(encoded, 0xCC, sizeof(encoded));
  ASSERT_EQ(165u, encodeOtaAbortFrame(owner.publicKey(), fx.target_public_key, before.imageHash,
                                     before.generation, signature, encoded, sizeof(encoded)));
  EXPECT_EQ(0xCC, encoded[165]);
  EXPECT_EQ(before.generation, getBE32(encoded + 97));
  EXPECT_EQ(0, std::memcmp(signature, encoded + 101, 64));
  OtaAbortFrame parsed;
  ASSERT_TRUE(parseOtaAbortFrame(encoded, 165, parsed));
  EXPECT_EQ(before.generation, parsed.generation);
  for (size_t len : {size_t(0), size_t(97), size_t(161), size_t(162), size_t(163), size_t(164), size_t(166)}) {
    EXPECT_FALSE(parseOtaAbortFrame(encoded, len, parsed));
    EXPECT_FALSE(fx.integration.handleReceivedFrame(encoded, len, 1));
  }
  uint8_t short_buffer[164]; std::memset(short_buffer, 0xEE, sizeof(short_buffer));
  EXPECT_EQ(0u, encodeOtaAbortFrame(owner.publicKey(), fx.target_public_key, before.imageHash,
                                   before.generation, signature, short_buffer, sizeof(short_buffer)));
  for (auto byte : short_buffer) EXPECT_EQ(0xEE, byte);
  AbortGenerationCleanupProbe cleanup;
  fx.integration.attachUnadmittedAbort(&cleanup, AbortGenerationCleanupProbe::invoke);
  const auto writes = fx.candidate_flash.programOpCount();
  for (size_t offset : {size_t(1), size_t(33), size_t(65), size_t(100), size_t(101)}) {
    SCOPED_TRACE(offset);
    encoded[offset] ^= 1;
    EXPECT_FALSE(fx.integration.handleReceivedFrame(encoded, 165, 2));
    encoded[offset] ^= 1;
  }
  // Correct current wire generation cannot rescue a signature made for another generation.
  buildAbortSignedMessage(fx.target_public_key, before.imageHash, before.generation - 1u, message);
  owner.sign(message, sizeof(message), encoded + 101);
  EXPECT_FALSE(fx.integration.handleReceivedFrame(encoded, 165, 3));
  buildAbortSignedMessage(fx.target_public_key, before.imageHash, before.generation, message);
  message[kAbortDomainLen - 1] = '1';
  owner.sign(message, kAbortSignedBytes - 4, encoded + 101);
  EXPECT_FALSE(fx.integration.handleReceivedFrame(encoded, 165, 3));
  buildAbortSignedMessage(fx.target_public_key, before.imageHash, before.generation, message);
  outsider.sign(message, sizeof(message), signature);
  encodeOtaAbortFrame(outsider.publicKey(), fx.target_public_key, before.imageHash,
                     before.generation, signature, encoded, sizeof(encoded));
  EXPECT_FALSE(fx.integration.handleReceivedFrame(encoded, 165, 4));
  EXPECT_EQ(writes, fx.candidate_flash.programOpCount());
  EXPECT_EQ(before.generation, receiver.status().generation);
  EXPECT_EQ(before.phase, receiver.status().phase);
  EXPECT_EQ(0u, cleanup.checks); EXPECT_EQ(0u, cleanup.cleanups);
}

TEST(LoraOtaAbortGeneration, UsbLocalStaleAbortPreservesReuploadedCacheAndOldLengthIsRejected) {
  using namespace mesh::ota::usb;
  LeanFixture fx;
  const uint8_t seed[32] = {0xA5};
  ::ota::test::Ed25519TestSigner self(seed);
  fx.integration.setLeanTargetPublicKey(self.publicKey());
  fx.integration.attachRfIdentity(&self, [](void* ctx, const uint8_t* data, size_t len, uint8_t out[64]) {
    static_cast<::ota::test::Ed25519TestSigner*>(ctx)->sign(data, len, out);
  }, nullptr, 907525);
  uint8_t image[168] = {0x53}, begin[kCacheBeginTotalBytes] = {kCommand, static_cast<uint8_t>(UsbOtaOp::CacheBegin)};
  std::memcpy(begin + 3, self.publicKey(), 32);
  fx.buildSmallManifest(image, sizeof(image), begin + 35);
  self.sign(begin + 35, 59, begin + 94);
  const auto first = fx.integration.handleUsbLocalControl(begin, sizeof(begin), self.publicKey());
  ASSERT_EQ(UsbOtaResult::Ok, first.result);
  uint8_t abort[kAbortTotalBytes] = {kCommand, static_cast<uint8_t>(UsbOtaOp::Abort)};
  auto& cache = fx.integration.leanReceiver();
  std::memcpy(abort + 34, cache.status().imageHash, 32);
  putBE32(abort + 66, first.generation);
  ASSERT_EQ(UsbOtaResult::Ok, fx.integration.handleUsbLocalControl(abort, sizeof(abort), self.publicKey()).result);
  begin[2] = kCacheBeginFlagReupload;
  ASSERT_EQ(UsbOtaResult::Ok, fx.integration.handleUsbLocalControl(begin, sizeof(begin), self.publicKey()).result);
  ASSERT_EQ(UsbOtaResult::Ok, cache.putBlock(0, image, 84));
  const auto before = cache.status();
  const auto writes = fx.candidate_flash.programOpCount(), erases = fx.image_flash.eraseOpCount();
  EXPECT_EQ(UsbOtaResult::BadRequest, fx.integration.handleUsbLocalControl(abort, 66, self.publicKey()).result);
  EXPECT_EQ(UsbOtaResult::BadRequest, fx.integration.handleUsbRemoteControl(abort, 66, nullptr, nullptr).result);
  const auto stale = fx.integration.handleUsbLocalControl(abort, sizeof(abort), self.publicKey());
  EXPECT_EQ(UsbOtaResult::Mismatch, stale.result);
  EXPECT_EQ(before.generation, stale.generation);
  EXPECT_EQ(1u, stale.durableReceivedBlocks);
  EXPECT_EQ(before.phase, cache.status().phase);
  EXPECT_EQ(writes, fx.candidate_flash.programOpCount()); EXPECT_EQ(erases, fx.image_flash.eraseOpCount());
  uint8_t reply[kReplyBytes + 1]; std::memset(reply, 0xCC, sizeof(reply));
  ASSERT_EQ(90u, encodeUsbOtaReply(stale, reply));
  EXPECT_EQ(2u, reply[1]); EXPECT_EQ(before.generation, getBE32(reply + 86)); EXPECT_EQ(0xCC, reply[90]);
  putBE32(abort + 66, before.generation);
  EXPECT_EQ(UsbOtaResult::Ok, fx.integration.handleUsbLocalControl(abort, sizeof(abort), self.publicKey()).result);
}

TEST(LoraOtaAbortGeneration, OriginalSignatureRetriesDurableCleanupWithoutAppendAfterRebootAndWrap) {
  using namespace mesh::ota;
  using namespace mesh::ota::usb;
  using Store = ::ota::storage::OtaCandidateStore;
  using Flash = ::ota::test::FakeNorFlash;
  for (const uint32_t generation : {1u, UINT32_MAX}) {
    LeanFixture fx;
    const uint8_t seed[32] = {0xA6};
    ::ota::test::Ed25519TestSigner owner(seed);
    fx.admins.add(owner.publicKey());
    uint8_t image[168] = {0x54}, canonical[59], signature[64], message[kAbortSignedBytes];
    fx.buildSmallManifest(image, sizeof(image), canonical); owner.sign(canonical, sizeof(canonical), signature);
    auto& receiver = fx.integration.leanReceiver();
    ASSERT_EQ(UsbOtaResult::Ok, receiver.begin(owner.publicKey(), canonical, signature, false, false));
    Store::Snapshot initial; ASSERT_TRUE(fx.candidate_store.load(initial));
    initial.sessionId = generation; ASSERT_TRUE(fx.candidate_store.append(initial)); receiver.restore();
    const auto before = receiver.status();
    buildAbortSignedMessage(fx.target_public_key, before.imageHash, generation, message);
    owner.sign(message, sizeof(message), signature);
    AbortGenerationCleanupProbe cleanup;
    fx.integration.attachUnadmittedAbort(&cleanup, AbortGenerationCleanupProbe::invoke);
    fx.candidate_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Before,
                                fx.candidate_flash.programOpCount() + 2});
    EXPECT_EQ(UsbOtaResult::IoError, receiver.abort(owner.publicKey(), signature, before.imageHash, generation));
    EXPECT_EQ(before.phase, receiver.status().phase);
    EXPECT_EQ(0u, cleanup.cleanups);
    fx.candidate_flash.clearFault();
    cleanup.failCleanup = true;
    ASSERT_EQ(UsbOtaResult::IoError, receiver.abort(owner.publicKey(), signature, before.imageHash, generation));
    ASSERT_EQ(Store::Phase::Aborted, receiver.status().phase);
    ASSERT_EQ(generation + 1u, receiver.status().generation);
    const auto writes = fx.candidate_flash.programOpCount();
    OtaFirmwareIntegration cold;
    cold.attachTrustProvider(&fx.trust); cold.attachStagingSink(&fx.guarded);
    cold.attachCandidateStore(&fx.candidate_store); cold.attachLeanSignatureVerifier(&fx.sig_verifier);
    cold.setLeanAdminCheck(&fx.admins, leanAdminCheckThunk); cold.setLeanTargetPublicKey(fx.target_public_key);
    cold.attachUnadmittedAbort(&cleanup, AbortGenerationCleanupProbe::invoke);
    EXPECT_EQ(UsbOtaResult::IoError, cold.leanReceiver().abort(owner.publicKey(), signature, before.imageHash, generation));
    EXPECT_EQ(writes, fx.candidate_flash.programOpCount());
    cleanup.failCleanup = false;
    EXPECT_EQ(UsbOtaResult::Ok, cold.leanReceiver().abort(owner.publicKey(), signature, before.imageHash, generation));
    EXPECT_EQ(writes, fx.candidate_flash.programOpCount());
    const auto cleanups = cleanup.cleanups;
    buildAbortSignedMessage(fx.target_public_key, before.imageHash, generation + 1u, message);
    owner.sign(message, sizeof(message), signature);
    EXPECT_EQ(UsbOtaResult::Ok,
              cold.leanReceiver().abort(owner.publicKey(), signature, before.imageHash, generation + 1u));
    EXPECT_EQ(writes, fx.candidate_flash.programOpCount());
    EXPECT_EQ(cleanups + 1u, cleanup.cleanups);
    EXPECT_EQ(UsbOtaResult::Mismatch,
              cold.leanReceiver().abort(owner.publicKey(), signature, before.imageHash, generation - 1u));
    fx.admins.count = 0;
    EXPECT_EQ(UsbOtaResult::Denied,
              cold.leanReceiver().abort(owner.publicKey(), signature, before.imageHash, generation + 1u));
    EXPECT_EQ(writes, fx.candidate_flash.programOpCount());
  }
}

TEST(LoraOtaIntegration, ProductionUsbRemoteControlRepliesAreCanonicalAndTransmitRealSignedMeshFrames) {
  using namespace mesh::ota;
  using namespace mesh::ota::usb;
  uint8_t seed[32] = {0x76}, target[32];
  ::ota::test::Ed25519TestSigner owner(seed);
  for (size_t i = 0; i < sizeof(target); ++i) target[i] = static_cast<uint8_t>(0xA0 + i);
  for (const auto op : {UsbOtaOp::Commit, UsbOtaOp::Abort}) {
    for (const auto expected : {UsbOtaResult::Ok, UsbOtaResult::Busy, UsbOtaResult::Mismatch, UsbOtaResult::Unavailable}) {
      if (op == UsbOtaOp::Abort && expected == UsbOtaResult::Mismatch) continue;
      SCOPED_TRACE(::testing::Message() << "op=" << unsigned(op) << " result=" << unsigned(expected));
      LeanFixture fx;
      fx.integration.setLeanTargetPublicKey(owner.publicKey());
      uint8_t image[20] = {0xB1}, canonical[59], signature[64];
      fx.buildSmallManifest(image, sizeof(image), canonical);
      owner.sign(canonical, sizeof(canonical), signature);
      uint8_t begin[kCacheBeginTotalBytes] = {kCommand, static_cast<uint8_t>(UsbOtaOp::CacheBegin)};
      std::memcpy(begin + 3, owner.publicKey(), 32);
      std::memcpy(begin + 35, canonical, 59);
      std::memcpy(begin + 94, signature, 64);
      auto& cache = fx.integration.leanReceiver();
      ASSERT_EQ(UsbOtaResult::Ok, cache.handleUsbCacheFrame(begin, sizeof(begin), owner.publicKey()));
      uint8_t put[5 + sizeof(image)] = {kCommand, static_cast<uint8_t>(UsbOtaOp::CachePut), 0, 0, sizeof(image)};
      std::memcpy(put + 5, image, sizeof(image));
      ASSERT_EQ(UsbOtaResult::Ok, cache.handleUsbCacheFrame(put, sizeof(put), owner.publicKey()));
      const uint8_t seal[] = {kCommand, static_cast<uint8_t>(UsbOtaOp::CacheSeal)};
      ASSERT_EQ(UsbOtaResult::Pending, cache.handleUsbCacheFrame(seal, sizeof(seal), owner.publicKey()));
      cache.loop();
      ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, cache.status().phase);
      ASSERT_TRUE(cache.status().localCache);

      FakeClock clock;
      PacketCaptureRadio radio;
      StaticPoolPacketManager manager(8);
      PacketBoundaryRng rng; PacketBoundaryRtc rtc; PacketBoundaryTables tables;
      ProductionPacketMesh mesh(radio, clock, rng, rtc, manager, tables);
      mesh.begin();
      mesh.getOtaIntegration() = fx.integration;
      auto& integration = mesh.getOtaIntegration();
      integration.attachRfIdentity(&owner, [](void* ctx, const uint8_t* data, size_t len, uint8_t out[64]) {
        static_cast<::ota::test::Ed25519TestSigner*>(ctx)->sign(data, len, out);
      }, nullptr, 907525);
      if (expected == UsbOtaResult::Unavailable) integration.attachRfIdentity(nullptr, nullptr, nullptr, 907525);
      if (expected == UsbOtaResult::Busy) {
        auto* ordinary = manager.allocNew();
        ASSERT_NE(nullptr, ordinary);
        ordinary->header = PAYLOAD_TYPE_ACK << PH_TYPE_SHIFT;
        ordinary->payload_len = 4;
        std::memset(ordinary->payload, 0x19, 4);
        mesh.sendZeroHop(ordinary);
      }
      struct SendContext {
        ProductionPacketMesh& mesh;
        StaticPoolPacketManager& manager;
        std::vector<uint8_t> frame;
        uint8_t target[32] = {};
        unsigned calls = 0;
      } send_ctx{mesh, manager, {}};
      const auto transmit = [](void* ctx, const uint8_t dest[32], const uint8_t* data, size_t len) {
        auto& sender = *static_cast<SendContext*>(ctx);
        ++sender.calls;
        sender.frame.assign(data, data + len);
        std::memcpy(sender.target, dest, 32);
        if (sender.mesh.isSendInProgress() || sender.manager.getOutboundTotal()) return false;
        auto* packet = sender.mesh.createOtaData(data, len);
        return packet && sender.mesh.sendFlood(packet, static_cast<uint32_t>(0), 2);
      };
      uint8_t command[kCommitTotalBytes] = {kCommand, static_cast<uint8_t>(op)};
      std::memcpy(command + 2, target, 32);
      const auto st = cache.status();
      const auto* hash = op == UsbOtaOp::Commit ? st.manifestHash : st.imageHash;
      std::memcpy(command + 34, hash, 32);
      putBE32(command + 66, op == UsbOtaOp::Commit ? st.counter : 0xA1B2C3D4u);
      if (expected == UsbOtaResult::Mismatch) command[34] ^= 1;
      const auto len = op == UsbOtaOp::Commit ? kCommitTotalBytes : kAbortTotalBytes;
      const auto image_writes = fx.image_flash.programOpCount();
      const auto journal_writes = fx.candidate_flash.programOpCount();
      const auto reply = integration.handleUsbRemoteControl(command, len, &send_ctx, transmit);
      ASSERT_EQ(expected, reply.result);
      uint8_t encoded[kReplyBytes];
      ASSERT_EQ(kReplyBytes, encodeUsbOtaReply(reply, encoded));
      EXPECT_EQ(kReplyCode, encoded[0]);
      EXPECT_EQ(kAbiVersion, encoded[1]);
      EXPECT_EQ(static_cast<uint8_t>(op), encoded[2]);
      EXPECT_EQ(static_cast<uint8_t>(expected), encoded[3]);
      EXPECT_EQ(static_cast<uint8_t>(UsbOtaPhase::Unknown), encoded[4]);
      EXPECT_EQ(kReplyFlagRemote, encoded[5]);
      EXPECT_EQ(0, std::memcmp(encoded + 6, target, 32));
      const uint8_t zero_snapshot[40] = {};
      EXPECT_EQ(0, std::memcmp(encoded + 38, zero_snapshot, sizeof(zero_snapshot)));
      EXPECT_EQ(kStatusAgeUnknown, getBE32(encoded + 78));
      EXPECT_EQ(0u, getBE32(encoded + 82));
      EXPECT_EQ(0u, getBE32(encoded + 86));
      EXPECT_EQ(image_writes, fx.image_flash.programOpCount());
      EXPECT_EQ(journal_writes, fx.candidate_flash.programOpCount());
      EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, integration.leanReceiver().status().phase);
      EXPECT_EQ(expected == UsbOtaResult::Ok || expected == UsbOtaResult::Busy ? 1u : 0u, send_ctx.calls);
      if (send_ctx.calls) {
        EXPECT_EQ(0, std::memcmp(send_ctx.target, target, 32));
        uint8_t message[kCommitSignedBytes];
        size_t message_len;
        const uint8_t* signed_bytes;
        OtaCommitFrame commit;
        OtaAbortFrame abort;
        if (op == UsbOtaOp::Commit) {
          ASSERT_TRUE(parseOtaCommitFrame(send_ctx.frame.data(), send_ctx.frame.size(), commit));
          EXPECT_EQ(0, std::memcmp(commit.target, target, 32));
          EXPECT_EQ(0, std::memcmp(commit.manifestHash, hash, 32));
          EXPECT_EQ(st.counter, commit.counter);
          message_len = buildCommitSignedMessage(target, hash, st.counter, message);
          signed_bytes = commit.signature;
        } else {
          ASSERT_TRUE(parseOtaAbortFrame(send_ctx.frame.data(), send_ctx.frame.size(), abort));
          EXPECT_EQ(0, std::memcmp(abort.target, target, 32));
          EXPECT_EQ(0, std::memcmp(abort.imageHash, hash, 32));
          EXPECT_EQ(0, std::memcmp(abort.signerPublicKey, owner.publicKey(), 32));
          EXPECT_EQ(0xA1B2C3D4u, abort.generation);
          EXPECT_EQ(165u, send_ctx.frame.size());
          EXPECT_EQ(abort.generation, getBE32(send_ctx.frame.data() + 97));
          message_len = buildAbortSignedMessage(target, hash, abort.generation, message);
          signed_bytes = abort.signature;
        }
        EXPECT_TRUE(fx.sig_verifier.verify(signed_bytes, 64, message, message_len, owner.publicKey(), 32));
      }
      if (expected == UsbOtaResult::Ok) {
        clock.advance(1); mesh.Dispatcher::loop();
        ASSERT_EQ(1, radio.sends);
        Packet emitted;
        ASSERT_TRUE(emitted.readFrom(radio.sent.data(), static_cast<uint8_t>(radio.sent.size())));
        EXPECT_EQ(PAYLOAD_TYPE_LORA_OTA, emitted.getPayloadType());
        ASSERT_EQ(send_ctx.frame.size(), emitted.payload_len);
        EXPECT_EQ(0, std::memcmp(emitted.payload, send_ctx.frame.data(), emitted.payload_len));
      }
      if (expected == UsbOtaResult::Busy) {
        clock.advance(1); mesh.Dispatcher::loop();
        clock.advance(1); mesh.Dispatcher::loop();
        ASSERT_FALSE(mesh.isSendInProgress());
        ASSERT_EQ(0, manager.getOutboundTotal());
        const auto signed_frame = send_ctx.frame;
        const auto retried = integration.handleUsbRemoteControl(command, len, &send_ctx, transmit);
        EXPECT_EQ(UsbOtaResult::Ok, retried.result);
        EXPECT_EQ(kReplyFlagRemote, retried.flags);
        EXPECT_EQ(UsbOtaPhase::Unknown, retried.phase);
        EXPECT_EQ(2u, send_ctx.calls);
        EXPECT_EQ(signed_frame, send_ctx.frame);
        EXPECT_EQ(image_writes, fx.image_flash.programOpCount());
        EXPECT_EQ(journal_writes, fx.candidate_flash.programOpCount());
      }
      if (const char* directory = std::getenv("OTA_USB_REMOTE_REPLY_PROOF_DIR")) {
        char path[512];
        const int size = std::snprintf(path, sizeof(path), "%s/op%02x-result%02x.bin", directory, unsigned(op), unsigned(expected));
        ASSERT_GT(size, 0); ASSERT_LT(static_cast<size_t>(size), sizeof(path));
        FILE* file = std::fopen(path, "wb"); ASSERT_NE(nullptr, file);
        const auto written = std::fwrite(encoded, 1, sizeof(encoded), file);
        EXPECT_EQ(0, std::fclose(file)); ASSERT_EQ(sizeof(encoded), written);
        const int request_size = std::snprintf(path, sizeof(path), "%s/op%02x-result%02x.request.bin",
                                               directory, unsigned(op), unsigned(expected));
        ASSERT_GT(request_size, 0); ASSERT_LT(static_cast<size_t>(request_size), sizeof(path));
        file = std::fopen(path, "wb"); ASSERT_NE(nullptr, file);
        const auto request_written = std::fwrite(command, 1, len, file);
        EXPECT_EQ(0, std::fclose(file)); ASSERT_EQ(len, request_written);
      }
    }
  }
}

TEST(LoraOtaIntegration, ProductionUsbRemoteControlRejectsMalformedFramesWithoutSigningOrQueuing) {
  mesh::ota::OtaFirmwareIntegration integration;
  uint8_t command[mesh::ota::usb::kCommitTotalBytes] = {66, 0x15};
  for (const auto len : {0u, 1u, 2u, 69u, 71u}) {
    const auto reply = integration.handleUsbRemoteControl(command, len, nullptr, nullptr);
    EXPECT_EQ(mesh::ota::usb::UsbOtaResult::BadRequest, reply.result);
    EXPECT_EQ(mesh::ota::usb::kReplyFlagRemote, reply.flags);
    EXPECT_EQ(mesh::ota::usb::UsbOtaPhase::Unknown, reply.phase);
    EXPECT_EQ(mesh::ota::usb::kStatusAgeUnknown, reply.statusAgeMs);
  }
  command[0] = 65;
  EXPECT_EQ(mesh::ota::usb::UsbOtaResult::BadRequest,
            integration.handleUsbRemoteControl(command, sizeof(command), nullptr, nullptr).result);
  command[0] = 66; command[1] = 0x17;
  EXPECT_EQ(mesh::ota::usb::UsbOtaResult::BadRequest,
            integration.handleUsbRemoteControl(command, 34, nullptr, nullptr).result);
}

TEST(LoraOtaIntegration, ProductionUsbEmptyLocalAbortAndCacheBeginErrorsNeverEchoRequestMetadata) {
  using namespace mesh::ota::usb;
  const UsbOtaResult results[] = {UsbOtaResult::NotFound, UsbOtaResult::NotFound, UsbOtaResult::Unavailable,
                                UsbOtaResult::Denied, UsbOtaResult::IoError, UsbOtaResult::Unavailable};
  uint8_t seed[32] = {0x37};
  ::ota::test::Ed25519TestSigner self(seed);
  for (unsigned kind = 0; kind < 6; ++kind) {
    SCOPED_TRACE(kind);
    LeanFixture fx;
    fx.integration.setLeanTargetPublicKey(self.publicKey());
    fx.integration.attachRfIdentity(&self, [](void* ctx, const uint8_t* bytes, size_t len, uint8_t out[64]) {
      static_cast<::ota::test::Ed25519TestSigner*>(ctx)->sign(bytes, len, out);
    }, nullptr, 907525);
    uint8_t command[kCacheBeginTotalBytes] = {kCommand};
    const auto op = kind < 3 ? UsbOtaOp::Abort : UsbOtaOp::CacheBegin;
    command[1] = static_cast<uint8_t>(op);
    const uint8_t* local_owner = kind == 2 ? nullptr : self.publicKey();
    if (kind < 3) {
      if (kind == 1) std::memcpy(command + 2, self.publicKey(), 32);
      std::memset(command + 34, 0xC9, 32);
      putBE32(command + 66, 0xCAFE1234);
    } else {
      uint8_t foreign_seed[32] = {0x38};
      ::ota::test::Ed25519TestSigner foreign(foreign_seed);
      auto& owner = kind == 3 ? foreign : self;
      uint8_t image[20] = {0x79};
      fx.buildSmallManifest(image, sizeof(image), command + 35, 5);
      std::memcpy(command + 3, owner.publicKey(), 32);
      owner.sign(command + 35, 59, command + 94);
      if (kind == 4) fx.image_flash.armFault({::ota::test::FakeNorFlash::OpKind::Erase,
          ::ota::test::FakeNorFlash::InjectionTiming::Before, fx.image_flash.eraseOpCount() + 1});
      if (kind == 5) fx.integration.attachStagingSink(nullptr);
    }
    const auto len = kind < 3 ? kAbortTotalBytes : kCacheBeginTotalBytes;
    const auto reply = fx.integration.handleUsbLocalControl(command, len, local_owner);
    ASSERT_EQ(results[kind], reply.result);
    EXPECT_FALSE(fx.integration.leanReceiver().status().valid);
    uint8_t encoded[kReplyBytes];
    ASSERT_EQ(kReplyBytes, encodeUsbOtaReply(reply, encoded));
    EXPECT_EQ(static_cast<uint8_t>(op), encoded[2]);
    EXPECT_EQ(static_cast<uint8_t>(results[kind]), encoded[3]);
    EXPECT_EQ(static_cast<uint8_t>(UsbOtaPhase::Unknown), encoded[4]);
    EXPECT_EQ(0u, encoded[5]);
    uint8_t target[32] = {};
    if (kind == 1) std::memcpy(target, self.publicKey(), 32);
    EXPECT_EQ(0, std::memcmp(target, encoded + 6, 32));
    const uint8_t empty[40] = {};
    EXPECT_EQ(0, std::memcmp(empty, encoded + 38, sizeof(empty)));
    EXPECT_EQ(kStatusAgeUnknown, getBE32(encoded + 78));
    EXPECT_EQ(0u, getBE32(encoded + 82));
    EXPECT_EQ(0u, getBE32(encoded + 86));
    if (const char* directory = std::getenv("OTA_USB_REMOTE_REPLY_PROOF_DIR")) {
      const auto save = [&](const char* suffix, const uint8_t* data, size_t bytes) {
        char path[512];
        const int length = std::snprintf(path, sizeof(path), "%s/local-op%02x-result%02x-case%u%s.bin",
                                         directory, unsigned(op), unsigned(results[kind]), kind, suffix);
        ASSERT_GT(length, 0); ASSERT_LT(static_cast<size_t>(length), sizeof(path));
        FILE* file = std::fopen(path, "wb"); ASSERT_NE(nullptr, file);
        const auto written = std::fwrite(data, 1, bytes, file);
        EXPECT_EQ(0, std::fclose(file)); ASSERT_EQ(bytes, written);
      };
      save("", encoded, sizeof(encoded)); save(".request", command, len);
      ASSERT_FALSE(HasFatalFailure());
    }
  }
}

TEST(LoraOtaIntegration, ProductionUsbCacheErrorKeepsActualExistingSnapshotInsteadOfRequestEcho) {
  using namespace mesh::ota::usb;
  LeanFixture fx;
  uint8_t seed[32] = {0x39}, foreign_seed[32] = {0x40};
  ::ota::test::Ed25519TestSigner self(seed), foreign(foreign_seed);
  uint8_t image[20] = {0x80}, command[kCacheBeginTotalBytes] = {kCommand, static_cast<uint8_t>(UsbOtaOp::CacheBegin)};
  std::memcpy(command + 3, self.publicKey(), 32);
  fx.buildSmallManifest(image, sizeof(image), command + 35, 5);
  self.sign(command + 35, 59, command + 94);
  const auto admitted = fx.integration.handleUsbLocalControl(command, sizeof(command), self.publicKey());
  ASSERT_EQ(UsbOtaResult::Ok, admitted.result);
  ASSERT_EQ(kReplyFlagSnapshotValid, admitted.flags);
  image[0] ^= 1;
  std::memcpy(command + 3, foreign.publicKey(), 32);
  fx.buildSmallManifest(image, sizeof(image), command + 35, 6);
  foreign.sign(command + 35, 59, command + 94);
  const auto denied = fx.integration.handleUsbLocalControl(command, sizeof(command), self.publicKey());
  ASSERT_EQ(UsbOtaResult::Denied, denied.result);
  ASSERT_EQ(kReplyFlagSnapshotValid, denied.flags);
  EXPECT_EQ(0, std::memcmp(admitted.manifestHash, denied.manifestHash, 32));
  EXPECT_EQ(admitted.counter, denied.counter);
  uint8_t encoded[kReplyBytes];
  ASSERT_EQ(kReplyBytes, encodeUsbOtaReply(denied, encoded));
  EXPECT_EQ(static_cast<uint8_t>(UsbOtaResult::Denied), encoded[3]);
  EXPECT_EQ(static_cast<uint8_t>(UsbOtaPhase::Receiving), encoded[4]);
  EXPECT_EQ(kReplyFlagSnapshotValid, encoded[5]);
  EXPECT_EQ(5u, getBE32(encoded + 74));
  EXPECT_EQ(0u, getBE32(encoded + 78));
}

TEST(LoraOtaIntegration, ProductionUsbLocalAbortUsesActualSelfSignatureAndPreservesExplicitReuploadGate) {
  using namespace mesh::ota::usb;
  uint8_t seed[32] = {0x41};
  ::ota::test::Ed25519TestSigner self(seed);
  for (const bool zero_target : {false, true}) {
    LeanFixture fx;
    fx.integration.setLeanTargetPublicKey(self.publicKey());
    fx.integration.attachRfIdentity(&self, [](void* ctx, const uint8_t* data, size_t len, uint8_t out[64]) {
      static_cast<::ota::test::Ed25519TestSigner*>(ctx)->sign(data, len, out);
    }, nullptr, 907525);
    uint8_t image[20] = {0x81}, begin[kCacheBeginTotalBytes] = {kCommand, static_cast<uint8_t>(UsbOtaOp::CacheBegin)};
    std::memcpy(begin + 3, self.publicKey(), 32);
    fx.buildSmallManifest(image, sizeof(image), begin + 35, 5);
    self.sign(begin + 35, 59, begin + 94);
    ASSERT_EQ(UsbOtaResult::Ok, fx.integration.handleUsbLocalControl(begin, sizeof(begin), self.publicKey()).result);
    const auto owned = fx.integration.leanReceiver().status();
    uint8_t abort[kAbortTotalBytes] = {kCommand, static_cast<uint8_t>(UsbOtaOp::Abort)};
    if (!zero_target) std::memcpy(abort + 2, self.publicKey(), 32);
    std::memcpy(abort + 34, owned.imageHash, 32);
    putBE32(abort + 66, owned.generation);
    const auto reply = fx.integration.handleUsbLocalControl(abort, sizeof(abort), self.publicKey());
    ASSERT_EQ(UsbOtaResult::Ok, reply.result);
    EXPECT_EQ(kReplyFlagSnapshotValid, reply.flags);
    EXPECT_EQ(UsbOtaPhase::Aborted, reply.phase);
    EXPECT_EQ(0, std::memcmp(reply.target, abort + 2, 32));
    EXPECT_EQ(0, std::memcmp(reply.manifestHash, owned.manifestHash, 32));
    EXPECT_EQ(owned.counter, reply.counter);
    EXPECT_EQ(owned.generation + 1u, reply.generation);
    EXPECT_EQ(UsbOtaResult::Denied, fx.integration.handleUsbLocalControl(begin, sizeof(begin), self.publicKey()).result);
  }
}

TEST(LoraOtaIntegration, ProductionMeshCreatesAndTransmitsFullOwnerSignedBlocksAndManifestsInEveryRoute) {
  using namespace mesh::ota;
  uint8_t seed[32] = {0x67};
  ::ota::test::Ed25519TestSigner owner(seed);
  uint8_t image[kOtaBlockMaxDataBytes];
  for (size_t i = 0; i < sizeof(image); ++i) image[i] = static_cast<uint8_t>(i);
  LeanFixture receiver;
  uint8_t canonical[59], signature[64], manifest_hash[32], target[32] = {0xA7};
  receiver.buildSmallManifest(image, sizeof(image), canonical);
  owner.sign(canonical, sizeof(canonical), signature);
  computeOtaManifestHash(canonical, manifest_hash);
  uint8_t block[kOtaOwnerSignedBlockMaxBytes], authorization[kOtaAuthorizationFrameBytes], targeted[164];
  const auto sign = [](void* ctx, const uint8_t* message, size_t len, uint8_t out[64]) {
    static_cast<::ota::test::Ed25519TestSigner*>(ctx)->sign(message, len, out);
  };
  ASSERT_EQ(183u, signAndEncodeOtaBlock(manifest_hash, 0, image, sizeof(image), &owner, sign,
                                       block, sizeof(block), owner.publicKey()));
  ASSERT_EQ(156u, encodeOtaAuthorizationFrame(owner.publicKey(), canonical, signature,
                                             authorization, sizeof(authorization)));
  ASSERT_EQ(164u, encodeOtaTargetAuthorization(target, owner.publicKey(), canonical, signature,
                                              targeted, sizeof(targeted)));
  ::ota::trust::Ed25519SignatureVerifier verifier;
  ASSERT_TRUE(verifier.verify(signature, sizeof(signature), canonical, sizeof(canonical), owner.publicKey(), 32));
  uint8_t message[kOtaBlockSignedMessageMaxBytes];
  const auto message_len = buildOtaBlockSignedMessage(manifest_hash, kOtaOwnerSignedBlockKind, 0,
                                                       image, sizeof(image), message);
  ASSERT_EQ(120u, message_len);
  ASSERT_TRUE(verifier.verify(block + 119, 64, message, message_len, owner.publicKey(), 32));
  const uint8_t* frames[] = {block, authorization, targeted};
  const size_t sizes[] = {sizeof(block), sizeof(authorization), sizeof(targeted)};
  for (size_t frame = 0; frame < 3; ++frame) {
    for (uint8_t route = 0; route < 7; ++route) {
      SCOPED_TRACE(::testing::Message() << "frame=" << frame << " route=" << unsigned(route));
      FakeClock clock;
      PacketCaptureRadio radio;
      StaticPoolPacketManager manager(8);
      PacketBoundaryRng rng;
      PacketBoundaryRtc rtc;
      PacketBoundaryTables tables;
      ProductionPacketMesh mesh(radio, clock, rng, rtc, manager, tables);
      mesh.begin();
      auto* packet = mesh.createOtaData(frames[frame], sizes[frame]);
      ASSERT_NE(nullptr, packet);
      ASSERT_EQ(PAYLOAD_TYPE_LORA_OTA, packet->getPayloadType());
      uint8_t path[MAX_PATH_SIZE];
      std::memset(path, 0x52, sizeof(path));
      uint16_t codes[2] = {0x1234, 0x5678};
      size_t path_bytes = 0;
      size_t scope_bytes = 0;
      if (route == 0) {
        mesh.sendZeroHop(packet);
      } else if (route <= 2) {
        path_bytes = route == 1 ? 3 : MAX_PATH_SIZE;
        mesh.sendDirect(packet, path, route == 1 ? 3 : ((2 - 1) << 6) | 32);
      } else {
        if (route >= 5) {
          ASSERT_TRUE(mesh.sendFlood(packet, codes, 0, 2));
          scope_bytes = 4;
        } else {
          ASSERT_TRUE(mesh.sendFlood(packet, static_cast<uint32_t>(0), 2));
        }
        if (route == 4 || route == 6) {
          packet->setPathHashSizeAndCount(2, 32);
          std::memcpy(packet->path, path, sizeof(path));
          path_bytes = MAX_PATH_SIZE;
        }
      }
      const size_t expected = 2 + scope_bytes + path_bytes + sizes[frame];
      ASSERT_EQ(expected, static_cast<size_t>(packet->getRawLength()));
      ASSERT_LE(expected, static_cast<size_t>(MAX_TRANS_UNIT));
      clock.advance(1);
      mesh.Dispatcher::loop();
      ASSERT_EQ(1, radio.sends);
      ASSERT_EQ(expected, radio.sent.size());
      Packet parsed;
      ASSERT_TRUE(parsed.readFrom(radio.sent.data(), static_cast<uint8_t>(radio.sent.size())));
      EXPECT_EQ(PAYLOAD_TYPE_LORA_OTA, parsed.getPayloadType());
      EXPECT_EQ(sizes[frame], parsed.payload_len);
      EXPECT_EQ(0, std::memcmp(parsed.payload, frames[frame], sizes[frame]));
      EXPECT_EQ(path_bytes, parsed.getPathByteLen());
      EXPECT_EQ(scope_bytes != 0, parsed.hasTransportCodes());
    }
  }
}

TEST(LoraOtaIntegration, ProductionPacketPayloadBoundaryRejectsOversizeAndEncryptedGroupBulk) {
  FakeClock clock;
  PacketCaptureRadio radio;
  StaticPoolPacketManager manager(8);
  PacketBoundaryRng rng;
  PacketBoundaryRtc rtc;
  PacketBoundaryTables tables;
  ProductionPacketMesh mesh(radio, clock, rng, rtc, manager, tables);
  mesh.begin();
  ASSERT_EQ(184, MAX_PACKET_PAYLOAD);
  ASSERT_EQ(255, MAX_TRANS_UNIT);
  uint8_t data[MAX_PACKET_PAYLOAD + 1] = {};
  const auto free_before = manager.getFreeCount();
  EXPECT_EQ(nullptr, mesh.createOtaData(data, sizeof(data)));
  EXPECT_EQ(free_before, manager.getFreeCount());
  auto* packet = mesh.createOtaData(data, MAX_PACKET_PAYLOAD);
  ASSERT_NE(nullptr, packet);
  uint16_t codes[2] = {0x1234, 0x5678};
  ASSERT_TRUE(mesh.sendFlood(packet, codes, 0, 2));
  packet->setPathHashSizeAndCount(2, 32);
  std::memset(packet->path, 0x52, sizeof(packet->path));
  EXPECT_EQ(254, packet->getRawLength());
  clock.advance(1);
  mesh.Dispatcher::loop();
  EXPECT_EQ(1, radio.sends);
  EXPECT_EQ(254u, radio.sent.size());
  GroupChannel channel = {};
  const auto before_group = manager.getFreeCount();
  EXPECT_EQ(nullptr, mesh.createGroupDatagram(PAYLOAD_TYPE_GRP_DATA, channel, data, 183));
  EXPECT_EQ(before_group, manager.getFreeCount());
}

TEST(LoraOtaLeanReceiver, NrfApplicationCeilingRejectsInvalidSizesBeforeAnyMutation) {
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
  ASSERT_EQ(643072u, maximum);
  descriptor.exactSizeBytes = maximum;
  EXPECT_TRUE(trust.verifyDescriptorPolicyOnly(descriptor));
  uint8_t canonical[59], signature[64];
  size_t canonical_len = 0;
  auto& receiver = fx.integration.leanReceiver();
  const auto image_erases = fx.image_flash.eraseOpCount();
  const auto image_programs = fx.image_flash.programOpCount();
  const auto candidate_erases = fx.candidate_flash.eraseOpCount();
  const auto candidate_programs = fx.candidate_flash.programOpCount();
  for (uint32_t size : {0u, maximum + 1u, kOtaMaxImageBytes, UINT32_MAX}) {
    descriptor.exactSizeBytes = size;
    EXPECT_FALSE(trust.verifyDescriptorPolicyOnly(descriptor));
    ASSERT_EQ(OtaDescriptorCodecResult::Ok,
              encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonical_len));
    owner.sign(canonical, sizeof(canonical), signature);
    EXPECT_EQ(Result::Denied, receiver.begin(owner.publicKey(), canonical, signature, false, false));
    EXPECT_EQ(image_erases, fx.image_flash.eraseOpCount());
    EXPECT_EQ(image_programs, fx.image_flash.programOpCount());
    EXPECT_EQ(candidate_erases, fx.candidate_flash.eraseOpCount());
    EXPECT_EQ(candidate_programs, fx.candidate_flash.programOpCount());
    EXPECT_FALSE(receiver.status().valid);
  }
  descriptor.exactSizeBytes = maximum;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok,
            encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonical_len));
  owner.sign(canonical, sizeof(canonical), signature);
  ASSERT_EQ(Result::Ok, receiver.begin(owner.publicKey(), canonical, signature, false, false));
  EXPECT_TRUE(receiver.status().valid);
  EXPECT_FALSE(receiver.status().localCache);
  EXPECT_EQ((maximum + mesh::ota::kOtaBlockMaxDataBytes - 1) / mesh::ota::kOtaBlockMaxDataBytes,
            receiver.status().totalBlocks);
}

TEST(LoraOtaLeanReceiver, NrfInstallationLimitDoesNotShrinkGenericPolicyOrOtherTargetCache) {
  using Result = mesh::ota::OtaLeanReceiver::Result;
  LeanFixture fx;
  mesh::ota::OtaNrf52FirmwareTrustProvider trust(fx.verifier, fx.image_region);
  mesh::ota::OtaFirmwareTrustProvider generic(fx.verifier, fx.image_region);
  fx.integration.attachTrustProvider(&trust);
  uint8_t seed[32] = {0x75};
  ::ota::test::Ed25519TestSigner owner(seed);
  fx.admins.add(owner.publicKey());
  const uint8_t image[1] = {0x48};
  auto descriptor = buildProtocolDescriptor(image, sizeof(image), 5);
  descriptor.exactSizeBytes = kOtaMaxImageBytes;
  ASSERT_EQ(708608u, descriptor.exactSizeBytes);
  EXPECT_TRUE(generic.verifyDescriptorPolicyOnly(descriptor));
  EXPECT_FALSE(trust.verifyDescriptorPolicyOnly(descriptor));
  descriptor.boardFamily = 0x4553;
  descriptor.boardVariant = 0x5033;  // Another target is valid only as non-installable cache.
  uint8_t canonical[59], signature[64];
  size_t canonical_len = 0;
  ASSERT_EQ(OtaDescriptorCodecResult::Ok,
            encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonical_len));
  owner.sign(canonical, sizeof(canonical), signature);
  auto& receiver = fx.integration.leanReceiver();
  ASSERT_EQ(Result::Ok, receiver.begin(owner.publicKey(), canonical, signature, false, false, true));
  EXPECT_TRUE(receiver.status().localCache);
  EXPECT_EQ((kOtaMaxImageBytes + mesh::ota::kOtaBlockMaxDataBytes - 1) / mesh::ota::kOtaBlockMaxDataBytes,
            receiver.status().totalBlocks);
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Receiving, receiver.status().phase);
}

TEST(LoraOtaIntegration, NrfLegacyDescriptorEntryPointUsesInternalLimitButGenericEntryPointDoesNot) {
  LeanFixture fx;
  uint8_t seed[32] = {0x75};
  ::ota::test::Ed25519TestSigner signer(seed);
  mesh::ota::OtaNrf52FirmwareTrustProvider trust(fx.verifier, fx.image_region,
                                                fx.sig_verifier, signer.publicKey());
  mesh::ota::OtaFirmwareTrustProvider generic(fx.verifier, fx.image_region,
                                             fx.sig_verifier, signer.publicKey());
  const uint8_t image[1] = {0x48};
  auto descriptor = buildProtocolDescriptor(image, sizeof(image), 5);
  uint8_t canonical[59], signature[64];
  size_t canonical_len = 0;
  for (uint32_t size : {643072u, 643073u, kOtaMaxImageBytes, UINT32_MAX, 0u}) {
    descriptor.exactSizeBytes = size;
    ASSERT_EQ(OtaDescriptorCodecResult::Ok,
              encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), canonical_len));
    signer.sign(canonical, sizeof(canonical), signature);
    EXPECT_EQ(size == 643072u, trust.verifyDescriptor(descriptor, signature, sizeof(signature)));
    if (size <= kOtaMaxImageBytes) {
      EXPECT_EQ(size != 0u, generic.verifyDescriptor(descriptor, signature, sizeof(signature)));
    }
  }
  EXPECT_EQ(0u, fx.image_flash.eraseOpCount());
  EXPECT_EQ(0u, fx.image_flash.programOpCount());
  EXPECT_EQ(0u, fx.candidate_flash.eraseOpCount());
  EXPECT_EQ(0u, fx.candidate_flash.programOpCount());
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

TEST(LoraOtaLeanReceiver, CompetingManifestFromDifferentAdminRemainsBusyWithReuploadRequested) {
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

  const auto erases = fx.image_flash.eraseOpCount();
  const auto programs = fx.candidate_flash.programOpCount();
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Busy,
            lean.begin(other_admin.publicKey(), canonical2, signature2, /*reupload=*/true, false));
  EXPECT_EQ(erases, fx.image_flash.eraseOpCount());
  EXPECT_EQ(programs, fx.candidate_flash.programOpCount());
  EXPECT_EQ(0, std::memcmp(owner.publicKey(), lean.status().ownerPublicKey, 32));
}

TEST(LoraOtaLeanReceiver, UsbReuploadCannotTakeOverActiveOrUnabortedFailedOwnerContentOrPurpose) {
  using namespace mesh::ota;
  using Result = mesh::ota::OtaLeanReceiver::Result;
  using Phase = ::ota::storage::OtaCandidateStore::Phase;
  for (const bool cache : {false, true}) {
    for (const auto phase : {Phase::Receiving, Phase::Verifying, Phase::Ready, Phase::Failed}) {
      LeanFixture fx;
      uint8_t seed[32] = {0x68}, other_seed[32] = {0x69};
      ::ota::test::Ed25519TestSigner owner(seed), other(other_seed);
      fx.admins.add(owner.publicKey());
      fx.admins.add(other.publicKey());
      uint8_t image[40] = {0x46}, canonical[59], signature[64];
      fx.buildSmallManifest(image, sizeof(image), canonical);
      owner.sign(canonical, sizeof(canonical), signature);
      auto& receiver = fx.integration.leanReceiver();
      ASSERT_EQ(Result::Ok, receiver.begin(owner.publicKey(), canonical, signature, false, false, cache));
      if (phase == Phase::Failed) image[0] ^= 1;
      ASSERT_EQ(Result::Ok, receiver.putBlock(0, image, sizeof(image)));
      if (phase != Phase::Receiving) ASSERT_EQ(Result::Pending, receiver.requestSeal());
      if (phase == Phase::Ready || phase == Phase::Failed) receiver.loop();
      ASSERT_EQ(phase, receiver.status().phase);
      const auto before = receiver.status();
      const auto image_erases = fx.image_flash.eraseOpCount();
      const auto image_programs = fx.image_flash.programOpCount();
      const auto metadata_erases = fx.candidate_flash.eraseOpCount();
      const auto metadata_programs = fx.candidate_flash.programOpCount();
      for (uint8_t mismatch = 0; mismatch < 3; ++mismatch) {
        const auto& signer = mismatch == 1 ? owner : other;
        uint8_t proposed[40] = {static_cast<uint8_t>(mismatch == 0 ? 0x46 : 0x48)};
        uint8_t frame[usb::kCacheBeginTotalBytes] = {usb::kCommand, static_cast<uint8_t>(usb::UsbOtaOp::CacheBegin),
                                                   usb::kCacheBeginFlagReupload};
        std::memcpy(frame + 3, signer.publicKey(), 32);
        fx.buildSmallManifest(proposed, sizeof(proposed), frame + 35, 6);
        signer.sign(frame + 35, 59, frame + 94);
        EXPECT_EQ(Result::Busy, receiver.handleUsbCacheFrame(frame, sizeof(frame), owner.publicKey()));
        EXPECT_EQ(before.phase, receiver.status().phase);
        EXPECT_EQ(before.transactionNonce, receiver.status().transactionNonce);
        EXPECT_EQ(before.receivedBlocks, receiver.status().receivedBlocks);
        EXPECT_EQ(0, std::memcmp(before.ownerPublicKey, receiver.status().ownerPublicKey, 32));
      }
      EXPECT_EQ(image_erases, fx.image_flash.eraseOpCount());
      EXPECT_EQ(image_programs, fx.image_flash.programOpCount());
      EXPECT_EQ(metadata_erases, fx.candidate_flash.eraseOpCount());
      EXPECT_EQ(metadata_programs, fx.candidate_flash.programOpCount());
      EXPECT_EQ(phase == Phase::Failed ? Result::Denied : Result::Ok,
                receiver.begin(owner.publicKey(), canonical, signature, false, false, cache));
      ASSERT_EQ(Result::Ok, receiver.begin(owner.publicKey(), canonical, signature, true, false, cache));
      EXPECT_EQ(Phase::Receiving, receiver.status().phase);
      EXPECT_EQ(0u, receiver.status().receivedBlocks);
      EXPECT_NE(before.transactionNonce, receiver.status().transactionNonce);
    }
  }
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
      mesh::ota::usb::buildAbortSignedMessage(fx.target_public_key, descriptor.sha256, lean.status().generation, abort_message);
  uint8_t abort_signature[64] = {};
  admin2.sign(abort_message, abort_message_len, abort_signature);
  EXPECT_EQ(mesh::ota::OtaLeanReceiver::Result::Ok,
            lean.abort(admin2.publicKey(), abort_signature, descriptor.sha256, lean.status().generation));
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
      mesh::ota::usb::buildAbortSignedMessage(fx.target_public_key, descriptor.sha256, lean.status().generation, abort_message);
  uint8_t abort_signature[64] = {};
  admin2.sign(abort_message, abort_message_len, abort_signature);
  uint8_t abort_frame[mesh::ota::kOtaAbortFrameBytes] = {};
  const size_t abort_frame_len = mesh::ota::encodeOtaAbortFrame(
      admin2.publicKey(), fx.target_public_key, descriptor.sha256, lean.status().generation,
      abort_signature, abort_frame, sizeof(abort_frame));
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
  bool normalTrafficActive = false;
  bool missingAdmissionRouteA = false;
  int authorizations = 0, initialData = 0, commits = 0;
  int firstReadmissionData = -1;
  uint32_t estimateMs = 20, completedMs = 20;
  uint32_t authorizationEstimateMs = 0, authorizationCompletedMs = 0;
  uint64_t controlTxMs = 0, dataTxMs = 0;
  bool advanceCompletionClock = false;
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
    if (h.missingAdmissionRouteA && h.lostAuthorization && frame[0] == kOtaTargetAuthorizationKind &&
        !std::memcmp(target, h.targets[0], 32)) return false;
    const bool authorization = frame[0] == kOtaTargetAuthorizationKind;
    const uint32_t estimate = authorization && h.authorizationEstimateMs ? h.authorizationEstimateMs : h.estimateMs;
    const uint32_t completed = authorization && h.authorizationCompletedMs ? h.authorizationCompletedMs : h.completedMs;
    if (!h.sender.fx.integration.canTransmit(h.now, category, estimate, true, h.normalTrafficActive)) return false;
    if (h.advanceCompletionClock) h.now += completed;
    EXPECT_TRUE(h.sender.fx.integration.recordTransmit(h.now, category, completed));
    if (category == meshcore::ota::protocol::OtaAirtimeCategory::Control) h.controlTxMs += completed;
    else h.dataTxMs += completed;
    if (frame[0] == kOtaCommitKind) ++h.commits;
    if (frame[0] == kOtaTargetAuthorizationKind) {
      EXPECT_EQ(164u, len);
      uint8_t tag[8];
      otaTargetTag(target, tag);
      EXPECT_EQ(0, std::memcmp(tag, frame + 1, sizeof(tag)));
      meshcore::ota::protocol::OtaDescriptor parsed;
      EXPECT_EQ(meshcore::ota::protocol::OtaDescriptorCodecResult::Ok,
                meshcore::ota::protocol::decodeOtaDescriptorCanonical(frame + 41, 59, parsed));
      EXPECT_EQ(h.image.size(), parsed.exactSizeBytes);
      ++h.authorizations;
      if (h.lostAuthorization && h.firstReadmissionData < 0 && !std::memcmp(target, h.targets[0], 32))
        h.firstReadmissionData = h.initialData;
    }
    if (h.loseReupload && !h.lostReupload && frame[0] == kOtaReuploadKind) {
      h.lostReupload = true; return true;
    }
    if (h.loseAuthorization && !h.lostAuthorization && frame[0] == kOtaTargetAuthorizationKind) {
      h.lostAuthorization = true; return true;
    }
    if (frame[0] == kOtaCensusPollKind) ++h.census;
    if (frame[0] == kOtaOwnerSignedBlockKind) {
      if (category == meshcore::ota::protocol::OtaAirtimeCategory::Relay) ++h.initialData;
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
  void expectByteExact(RfNode& node) {
    std::vector<uint8_t> received(image.size());
    for (size_t offset = 0; offset < received.size(); offset += 84) {
      ASSERT_EQ(IOtaStagingSink::Result::Ok, node.fx.staging.readChunk(
          offset, received.data() + offset, std::min<size_t>(84, received.size() - offset)));
    }
    EXPECT_EQ(image, received);
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

TEST(LoraOtaRfProduct, DirectedLostBeginReadmitsBeforeInitialSweepAtTwoPercent) {
  RfProductHarness h;
  h.loseAuthorization = true;
  h.prepare(84 * 512 + 7, usb::kStartModeDirected);
  ASSERT_FLOAT_EQ(2.0f, h.sender.fx.integration.dutyCyclePercent());
  h.normalTrafficActive = true;
  for (int i = 0; i < 30; ++i) h.step();
  EXPECT_EQ(0, h.authorizations);
  EXPECT_EQ(0, h.initialData);
  h.normalTrafficActive = false;
  for (int i = 0; i < 160 && h.a.fx.integration.leanReceiver().status().receivedBlocks == 0; ++i) h.step();
  ASSERT_TRUE(h.lostAuthorization);
  ASSERT_GT(h.a.fx.integration.leanReceiver().status().receivedBlocks, 0);
  ASSERT_GE(h.firstReadmissionData, 32);
  EXPECT_LT(h.firstReadmissionData, 513);
  EXPECT_LT(h.initialData, 513);
  EXPECT_LE(h.authorizations, 1 + h.initialData / 32);
  EXPECT_LE(h.sender.fx.integration.status(h.now).dutyUsedMs, 72000u);
  for (int i = 0; i < 2000 && !h.ready(h.a); ++i) h.step();
  EXPECT_TRUE(h.ready(h.a));
  h.expectByteExact(h.a);
  EXPECT_EQ(0, h.commits);
}

TEST(LoraOtaRfProduct, BackgroundLostBeginReadmitsWithoutBlockingHealthyFleetAtTwoPercent) {
  RfProductHarness h;
  h.loseAuthorization = true;
  h.prepare(84 * 512 + 7, usb::kStartModeBackground);
  for (int i = 0; i < 160 && h.a.fx.integration.leanReceiver().status().receivedBlocks == 0; ++i) {
    const int before = h.initialData + h.authorizations + h.census;
    h.normalTrafficActive = i % 7 == 0;
    h.step();
    if (h.normalTrafficActive) EXPECT_EQ(before, h.initialData + h.authorizations + h.census);
  }
  ASSERT_TRUE(h.lostAuthorization);
  ASSERT_GT(h.a.fx.integration.leanReceiver().status().receivedBlocks, 0);
  ASSERT_GT(h.b.fx.integration.leanReceiver().status().receivedBlocks, 0);
  EXPECT_LT(h.firstReadmissionData, 513);
  EXPECT_LT(h.initialData, 513);
  EXPECT_LE(h.authorizations, 2 + h.initialData / 32);
  h.normalTrafficActive = false;
  for (int i = 0; i < 3000 && !(h.ready(h.a) && h.ready(h.b)); ++i) h.step();
  EXPECT_TRUE(h.ready(h.a));
  EXPECT_TRUE(h.ready(h.b));
  h.expectByteExact(h.a);
  h.expectByteExact(h.b);
  EXPECT_LE(h.sender.fx.integration.status(h.now).dutyUsedMs, 72000u);
  EXPECT_EQ(0, h.commits);
}

class LoraOtaRfPacedAdmission : public testing::TestWithParam<uint8_t> {};

TEST_P(LoraOtaRfPacedAdmission, ScarceDutyCreditAcrossClockWrapAdmitsDataAndLostBeginBeforeFullSweep) {
  RfProductHarness h;
  h.loseAuthorization = true;
  h.prepare(537816, GetParam());
  ASSERT_EQ(6403u, h.sender.fx.integration.leanReceiver().status().totalBlocks);
  h.estimateMs = 200; h.completedMs = 300;
  h.authorizationEstimateMs = 300; h.authorizationCompletedMs = 400;
  h.advanceCompletionClock = true;
  const uint32_t start = UINT32_MAX - 120000u;
  auto& integration = h.sender.fx.integration;
  using Category = meshcore::ota::protocol::OtaAirtimeCategory;
  for (uint32_t i = 0; i < 180; ++i) {
    const uint32_t time = start - 3590000u + i * 20000u;
    ASSERT_TRUE(integration.canTransmit(time, Category::Repair, 254, true, false));
    ASSERT_TRUE(integration.recordTransmit(time, Category::Repair, 399));
  }
  h.now = start;
  ASSERT_FLOAT_EQ(2.0f, integration.dutyCyclePercent());
  ASSERT_EQ(3600000u, integration.status(h.now).dutyWindowMs);
  ASSERT_EQ(72000u, integration.status(h.now).dutyBudgetMs);
  ASSERT_EQ(71820u, integration.status(h.now).dutyUsedMs);
  for (int i = 0; i < 2500 && h.a.fx.integration.leanReceiver().status().receivedBlocks == 0; ++i) {
    h.normalTrafficActive = i % 9 == 0;
    const int before = h.initialData + h.authorizations + h.census;
    h.step();
    if (h.normalTrafficActive) EXPECT_EQ(before, h.initialData + h.authorizations + h.census);
    ASSERT_LE(integration.status(h.now).dutyUsedMs, 72000u);
  }
  SCOPED_TRACE(testing::Message() << "initial DATA=" << h.initialData
      << " AUTH=" << h.authorizations << " first readmission DATA=" << h.firstReadmissionData
      << " clock=" << h.now << " used=" << integration.status(h.now).dutyUsedMs);
  ASSERT_TRUE(h.lostAuthorization);
  ASSERT_GT(h.a.fx.integration.leanReceiver().status().receivedBlocks, 0);
  if (GetParam() == usb::kStartModeBackground)
    EXPECT_GT(h.b.fx.integration.leanReceiver().status().receivedBlocks, 0);
  EXPECT_LT(h.now, start);
  EXPECT_LT(h.firstReadmissionData, 6403);
  EXPECT_LT(h.initialData, 6403);
  EXPECT_LE(h.authorizations, (GetParam() == usb::kStartModeBackground ? 2 : 1) + h.initialData / 32);
  for (int i = 0; i < 180000 && !(h.ready(h.a) &&
      (GetParam() != usb::kStartModeBackground || h.ready(h.b))); ++i) {
    h.normalTrafficActive = i % 9 == 0;
    const int before = h.initialData + h.authorizations + h.census + h.repairs.size();
    h.step();
    if (h.normalTrafficActive)
      EXPECT_EQ(before, h.initialData + h.authorizations + h.census + h.repairs.size());
    ASSERT_LE(integration.status(h.now).dutyUsedMs, 72000u);
  }
  ASSERT_TRUE(h.ready(h.a));
  h.expectByteExact(h.a);
  if (GetParam() == usb::kStartModeBackground) {
    ASSERT_TRUE(h.ready(h.b));
    h.expectByteExact(h.b);
  }
  EXPECT_EQ(6403, h.initialData);
  EXPECT_LE(h.authorizations, (GetParam() == usb::kStartModeBackground ? 2 : 1) + h.initialData / 32);
  EXPECT_LE(h.controlTxMs * 10u, h.dataTxMs);
  EXPECT_GE(h.now - start, 24u * 3600000u);
  EXPECT_LE(h.now - start, 72u * 3600000u);
  RecordProperty("campaign_ms", h.now - start);
  RecordProperty("control_tx_ms", std::to_string(h.controlTxMs));
  RecordProperty("data_tx_ms", std::to_string(h.dataTxMs));
  RecordProperty("authorization_packets", h.authorizations);
  RecordProperty("initial_data_packets", h.initialData);
  RecordProperty("first_readmission_after_data", h.firstReadmissionData);
  EXPECT_EQ(0, h.commits);
}

INSTANTIATE_TEST_SUITE_P(BothOnMeshModes, LoraOtaRfPacedAdmission,
                        testing::Values(usb::kStartModeDirected, usb::kStartModeBackground),
                        [](const testing::TestParamInfo<uint8_t>& info) {
                          return info.param == usb::kStartModeDirected ? "Directed" : "Background";
                        });

TEST(LoraOtaRfProduct, FailedAdmissionRouteCannotBlockHealthyMulticastOrConsumeDuty) {
  RfProductHarness h;
  h.loseAuthorization = true;
  h.missingAdmissionRouteA = true;
  h.prepare(84 * 512 + 7, usb::kStartModeBackground);
  for (int i = 0; i < 800 && !h.ready(h.b); ++i) h.step();
  ASSERT_TRUE(h.ready(h.b));
  EXPECT_FALSE(h.a.fx.integration.leanReceiver().status().valid);
  h.expectByteExact(h.b);
  EXPECT_EQ(513, h.initialData);
  EXPECT_LE(h.authorizations, 2 + h.initialData / 32);
  EXPECT_LE(h.sender.fx.integration.status(h.now).dutyUsedMs, 72000u);
  EXPECT_EQ(0, h.commits);
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
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, st.generation, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash, st.generation));
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
  st = receiver.status();
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, st.generation, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash, st.generation));
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
  auto st = receiver.status();
  uint8_t message[usb::kAbortSignedBytes], signature[64];
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, st.generation, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash, st.generation));
  const auto erases = h.a.fx.image_flash.eraseOpCount();
  for (int i = 0; i < 500; ++i) {
    h.step();
    if (h.a.fx.image_flash.eraseOpCount() > erases && receiver.status().receivedBlocks > 0) break;
  }
  ASSERT_GT(h.a.fx.image_flash.eraseOpCount(), erases);
  ASSERT_GT(receiver.status().receivedBlocks, 0);
  st = receiver.status();
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, st.generation, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash, st.generation));
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
  auto st = receiver.status();
  uint8_t message[usb::kAbortSignedBytes], signature[64];
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, st.generation, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash, st.generation));
  h.loseReupload = true;
  for (int i = 0; i < 500 && !h.ready(h.a); ++i) h.step();
  ASSERT_TRUE(h.lostReupload);
  ASSERT_TRUE(h.ready(h.a));
  st = receiver.status();
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, st.generation, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(h.sender.signer.publicKey(), signature, st.imageHash, st.generation));
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
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), original.imageHash, original.generation, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok,
            receiver.abort(h.sender.signer.publicKey(), signature, original.imageHash, original.generation));
  h.uploader.stop(h.sender.fx.integration);
  auto& cache = h.sender.fx.integration.leanReceiver();
  const auto cached = cache.status();
  usb::buildAbortSignedMessage(h.sender.signer.publicKey(), cached.imageHash, cached.generation, message);
  h.sender.signer.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok,
            cache.abort(h.sender.signer.publicKey(), signature, cached.imageHash, cached.generation, true));
  const uint8_t new_owner_seed[32] = {7};
  h.sender.signer = ::ota::test::Ed25519TestSigner(new_owner_seed);
  h.sender.fx.integration.setLeanTargetPublicKey(h.sender.signer.publicKey());
  h.a.fx.admins.count = 0;
  h.a.fx.admins.add(h.sender.signer.publicKey());
  h.image.assign(257, 0x57);
  uint8_t canonical[59];
  h.sender.fx.buildSmallManifest(h.image.data(), h.image.size(), canonical);
  h.sender.signer.sign(canonical, sizeof(canonical), signature);
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
  usb::buildAbortSignedMessage(h.a.signer.publicKey(), st.imageHash, st.generation, abort_message);
  h.sender.signer.sign(abort_message, sizeof(abort_message), abort_signature);
  EXPECT_EQ(usb::UsbOtaResult::TooLate,
            receiver.abort(h.sender.signer.publicKey(), abort_signature, st.imageHash, st.generation));
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
  bool fail = false, fail_with_output = false;
  ::ota::storage::XiaoOtaExtentResolutionStep stepExtentResolution(uint32_t, const uint8_t** out, uint32_t* extent) override {
    if (fail) return ::ota::storage::XiaoOtaExtentResolutionStep::Failed;
    *out = image.data(); *extent = image.size();
    if (fail_with_output) return ::ota::storage::XiaoOtaExtentResolutionStep::Failed;
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
  void setState(uint32_t phase, uint32_t counter = 5, uint64_t nonce = 17,
                const uint8_t* candidate_hash = nullptr, const uint8_t* backup_hash = nullptr,
                uint32_t backup_extent = 4096) {
    using Reader = ::ota::storage::XiaoOtaStateReader;
    ::ota::trust::Sha256::hash(accessor.image.data(), accessor.image.size(), hash);
    uint8_t bytes[Reader::kRecordBytes] = {};
    le32(bytes, Reader::kMagic); bytes[4] = 1; bytes[6] = Reader::kRecordBytes; le32(bytes + 8, 1);
    le32(bytes + 12, nonce); le32(bytes + 16, nonce >> 32); le32(bytes + 20, phase);
    le32(bytes + 28, backup_extent);
    le32(bytes + 32, counter);
    std::memcpy(bytes + 44, candidate_hash ? candidate_hash : hash, 32);
    std::memcpy(bytes + 76, backup_hash ? backup_hash : hash, 32);
    std::memcpy(bytes + 108, hash, 32);
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

class LifecycleCommandProvider : public IOtaInstallCommandProviderV3 {
public:
  explicit LifecycleCommandProvider(std::vector<uint8_t>& running) : running_(running) {}
  bool buildInstallCommandV3(const uint8_t canonical[59], const uint8_t signature[64],
                             const uint8_t owner[32], const OtaSessionId& session, const uint8_t controller[32],
                             ::ota::storage::XiaoOtaCommandV3Fields& out) override {
    using Bridge = ::ota::storage::XiaoOtaActiveExtentBridge;
    ::ota::storage::XiaoOtaBank0Settings bank;
    bank.bank_0 = ::ota::storage::kBankValidApp;
    bank.bank_0_size = running_.size();
    bank.bank_0_crc = Bridge::crc16Compute(running_.data(), running_.size());
    const auto actual = Bridge::resolve(bank, running_.data(), running_.size());
    if (!actual.active_image_extent) return false;
    std::memcpy(out.wire_descriptor, canonical, 59);
    std::memcpy(out.signature_ed25519, signature, 64);
    std::memcpy(out.admitted_signer_public_key_ed25519, owner, 32);
    out.transaction_nonce = computeOtaTransactionNonce(controller, session, canonical);
    out.active_image_extent = actual.active_image_extent;
    std::memcpy(out.active_image_hash_sha256, actual.active_image_hash_sha256, 32);
    return out.transaction_nonce != 0;
  }
private:
  std::vector<uint8_t>& running_;
};

struct RefusalRunningContext : IOtaNrf52RunningContext {
  std::vector<uint8_t>& image;
  bool fail = false, invalid = false, badCrc = false, tailErased = true;
  uint16_t bank1 = 0xff;
  mutable uint32_t reads = 0;
  uint32_t failAt = 0, changeAt = 0;
  explicit RefusalRunningContext(std::vector<uint8_t>& bytes) : image(bytes) {}
  bool read(OtaNrf52RunningContext& out) const override {
    ++reads;
    if (fail || reads == failAt) return false;
    if (reads == changeAt) image.back() ^= 1;
    out = OtaNrf52RunningContext();
    out.image = image.data(); out.capacity = image.size(); out.settingsTailErased = tailErased;
    out.settings[0] = invalid ? 0xff : 1;
    const auto crc = ::ota::storage::XiaoOtaActiveExtentBridge::crc16Compute(image.data(), image.size()) ^ (badCrc ? 1 : 0);
    out.settings[2] = crc; out.settings[3] = crc >> 8;
    out.settings[4] = bank1; out.settings[5] = bank1 >> 8;
    LifecycleFixture::le32(out.settings + 8, image.size());
    return true;
  }
};

struct UnadmittedFixture {
  LeanFixture fx;
  LifecycleFixture boot;
  ::ota::test::FakeNorFlash command_flash{8192, 4096};
  ::ota::platform::FlashRegion command{command_flash, 0, 8192};
  LifecycleCommandProvider provider{boot.accessor.image};
  RefusalRunningContext running{boot.accessor.image};
  bool qualified = true;
  uint32_t target;
  uint8_t role;
  uint8_t seed[32] = {0x6d};
  ::ota::test::Ed25519TestSigner owner{seed};
  ::ota::trust::DeviceTrustAnchor anchor;
  std::unique_ptr<OtaBoardFailClosedMonotonicCounter> counter;
  std::unique_ptr<::ota::trust::DescriptorVerifier> verifier;
  std::unique_ptr<OtaNrf52FirmwareTrustProvider> trust;
  OtaFirmwareStorageSink sink{fx.image_region, &command, &provider};
  OtaBoardUnadmittedCommandRecovery recovery;
  std::vector<uint8_t> image = std::vector<uint8_t>(168, 0x47);
  uint8_t canonical[59] = {}, signature[64] = {};
  explicit UnadmittedFixture(uint32_t board = 0x584E3430u, uint8_t compiled_role = 0)
      : target(board), role(compiled_role), anchor(makeLeanTrustAnchor()),
        recovery(command, boot.state, boot.floor, fx.image_region, fx.sig_verifier, running, qualified, board, compiled_role) {
    anchor.expected_target_id = target; anchor.expected_role_id = role; anchor.supported_boot_capability_flags = 1;
    reattach();
  }
  void reattach() {
    counter.reset(new OtaBoardFailClosedMonotonicCounter(boot.floor));
    verifier.reset(new ::ota::trust::DescriptorVerifier(fx.hasher, fx.sig_verifier, *counter, anchor));
    trust.reset(new OtaNrf52FirmwareTrustProvider(*verifier, fx.image_region));
    fx.integration.attachTrustProvider(trust.get());
    fx.integration.attachStagingSink(&sink);
    fx.integration.attachCandidateStore(&fx.candidate_store);
    fx.integration.attachLeanSignatureVerifier(&fx.sig_verifier);
    fx.integration.setLeanAdminCheck(&fx.admins, &leanAdminCheckThunk);
    fx.integration.setLeanTargetPublicKey(fx.target_public_key);
    fx.integration.attachBootLifecycle(&boot.observer, [](void* ctx, OtaBootLifecycleEvidence& out) {
      return static_cast<OtaBoardBootLifecycleObserver*>(ctx)->read(true, out);
    });
    fx.integration.attachUnadmittedAbort(&recovery, &OtaBoardUnadmittedCommandRecovery::invoke);
    fx.admins.add(owner.publicKey());
  }
  void manifest(uint32_t count) {
    auto d = buildProtocolDescriptor(image.data(), image.size(), count);
    d.boardFamily = target >> 16; d.boardVariant = target; d.role = role; d.minBootloaderCapabilities = 1;
    size_t len = 0;
    ASSERT_EQ(OtaDescriptorCodecResult::Ok, encodeOtaDescriptorCanonical(d, canonical, sizeof(canonical), len));
    owner.sign(canonical, sizeof(canonical), signature);
  }
  void stage(uint32_t count = 5, bool reupload = false, bool bad = false) {
    manifest(count);
    auto& receiver = fx.integration.leanReceiver();
    ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.begin(owner.publicKey(), canonical, signature, reupload, false));
    for (uint16_t block = 0; block < image.size() / 84; ++block) {
      uint8_t bytes[84]; std::memcpy(bytes, image.data() + block * 84, sizeof(bytes));
      if (bad && block == 0) bytes[12] ^= 1;
      ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.putBlock(block, bytes, sizeof(bytes)));
    }
    ASSERT_EQ(usb::UsbOtaResult::Pending, receiver.requestSeal());
    receiver.loop();
    ASSERT_EQ(bad ? ::ota::storage::OtaCandidateStore::Phase::Failed :
                   ::ota::storage::OtaCandidateStore::Phase::Ready, receiver.status().phase);
  }
  void commit() {
    auto& receiver = fx.integration.leanReceiver();
    const auto st = receiver.status();
    uint8_t message[usb::kCommitSignedBytes], sig[64];
    usb::buildCommitSignedMessage(fx.target_public_key, st.manifestHash, st.counter, message);
    owner.sign(message, sizeof(message), sig);
    ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.commit(st.counter, sig));
  }
  usb::UsbOtaResult abort() {
    const auto st = fx.integration.leanReceiver().status();
    uint8_t message[usb::kAbortSignedBytes], sig[64];
    usb::buildAbortSignedMessage(fx.target_public_key, st.imageHash, st.generation, message);
    owner.sign(message, sizeof(message), sig);
    return fx.integration.leanReceiver().abort(owner.publicKey(), sig, st.imageHash, st.generation);
  }
  void recordCompletedRollback() {
    ::ota::trust::Sha256::hash(boot.accessor.image.data(), boot.accessor.image.size(), boot.hash);
    boot.setFloor(4);
    reattach();
    stage(); ASSERT_FALSE(::testing::Test::HasFatalFailure());
    commit(); ASSERT_FALSE(::testing::Test::HasFatalFailure());
    const auto st = fx.integration.leanReceiver().status();
    boot.setState(::ota::storage::XiaoOtaStateReader::kPhaseFailedMax, st.counter, st.transactionNonce,
                  st.imageHash, boot.hash, boot.accessor.image.size());
    for (int tick = 0; tick < 10; ++tick) boot.observer.tick(true);
    ASSERT_EQ(usb::UsbOtaPhase::Failed, fx.integration.reportedPhase());
  }
};

struct ConsecutiveRollbackFixture {
  UnadmittedFixture f;
  std::vector<uint8_t> first_image, second_image;
  uint8_t commands[2][::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes] = {};
  std::unique_ptr<OtaBoardBootLifecycleObserver> completed;
  explicit ConsecutiveRollbackFixture(uint32_t board = 0x584E3430u, uint8_t role = 0) : f(board, role) {}
  void prepare() {
    using Cmd = ::ota::storage::XiaoOtaCommandRecordV3;
    first_image = f.image;
    f.recordCompletedRollback(); ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_TRUE(Cmd::readNewest(f.command, commands[0]));
    f.image[12] ^= 1;
    second_image = f.image;
    f.stage(6); ASSERT_FALSE(::testing::Test::HasFatalFailure());
    f.commit(); ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_TRUE(Cmd::readNewest(f.command, commands[1]));
    const auto st = f.fx.integration.leanReceiver().status();
    ASSERT_TRUE(::ota::platform::isOk(f.boot.state.eraseSector(0)));
    ASSERT_TRUE(::ota::platform::isOk(f.boot.state.eraseSector(4096)));
    f.boot.setState(::ota::storage::XiaoOtaStateReader::kPhaseFailedMax, st.counter, st.transactionNonce,
                    st.imageHash, f.boot.hash, f.boot.accessor.image.size());
    completed.reset(new OtaBoardBootLifecycleObserver(f.boot.state, f.boot.floor, f.boot.accessor));
    for (int tick = 0; tick < 10; ++tick) completed->tick(true);
    f.fx.integration.attachBootLifecycle(completed.get(), [](void* ctx, OtaBootLifecycleEvidence& out) {
      return static_cast<OtaBoardBootLifecycleObserver*>(ctx)->read(true, out);
    });
    ASSERT_EQ(usb::UsbOtaPhase::Failed, f.fx.integration.reportedPhase());
  }
  void sequence(uint32_t slot, uint32_t value) {
    using Cmd = ::ota::storage::XiaoOtaCommandRecordV3;
    LifecycleFixture::le32(commands[slot] + 8, value);
    LifecycleFixture::le32(commands[slot] + Cmd::kCrcOffset,
        ::ota::storage::Crc32::computeFinalized(commands[slot], Cmd::kCrcOffset));
    ASSERT_TRUE(::ota::platform::isOk(f.command.eraseSector(slot * 4096)));
    ASSERT_TRUE(::ota::platform::isOk(f.command.program(slot * 4096, commands[slot], sizeof(commands[slot]))));
  }
};
}

TEST(LoraOtaAbortGeneration, OriginalRfAbortRetriesRealUnadmittedNrfCleanupAfterAppendAndEraseFailures) {
  using namespace mesh::ota;
  using namespace mesh::ota::usb;
  using Phase = ::ota::storage::OtaCandidateStore::Phase;
  using Flash = ::ota::test::FakeNorFlash;
  for (const uint32_t board : {0x584E3430u, 0x53435031u}) for (const uint8_t role : {0, 1}) {
    SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role));
    UnadmittedFixture f(board, role);
    f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
    auto& receiver = f.fx.integration.leanReceiver();
    const auto before = receiver.status();
    uint8_t message[kAbortSignedBytes], signature[64], captured[kOtaAbortFrameBytes];
    buildAbortSignedMessage(f.fx.target_public_key, before.imageHash, before.generation, message);
    f.owner.sign(message, sizeof(message), signature);
    encodeOtaAbortFrame(f.owner.publicKey(), f.fx.target_public_key, before.imageHash,
                       before.generation, signature, captured, sizeof(captured));
    // Real command policy refuses the now-different running original; it has not been admitted.
    f.boot.accessor.image.back() ^= 1;
    const auto command_erases = f.command_flash.eraseOpCount();
    f.fx.candidate_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Before,
                                  f.fx.candidate_flash.programOpCount() + 2});
    EXPECT_FALSE(f.fx.integration.handleReceivedFrame(captured, sizeof(captured), 1));
    EXPECT_EQ(before.generation, receiver.status().generation);
    EXPECT_EQ(Phase::Committed, receiver.status().phase);
    EXPECT_EQ(command_erases, f.command_flash.eraseOpCount());
    f.fx.candidate_flash.clearFault();
    f.fx.integration = OtaFirmwareIntegration(); f.reattach();
    f.command_flash.armFault({Flash::OpKind::Erase, Flash::InjectionTiming::Before,
                             f.command_flash.eraseOpCount() + 1});
    EXPECT_FALSE(f.fx.integration.handleReceivedFrame(captured, sizeof(captured), 2));
    ASSERT_EQ(Phase::Aborted, f.fx.integration.leanReceiver().status().phase);
    ASSERT_EQ(before.generation + 1u, f.fx.integration.leanReceiver().status().generation);
    f.command_flash.clearFault();
    f.fx.integration = OtaFirmwareIntegration(); f.reattach();
    const auto journal_writes = f.fx.candidate_flash.programOpCount();
    f.command_flash.armFault({Flash::OpKind::Erase, Flash::InjectionTiming::Before,
                             f.command_flash.eraseOpCount() + 1});
    EXPECT_FALSE(f.fx.integration.handleReceivedFrame(captured, sizeof(captured), 3));
    EXPECT_EQ(journal_writes, f.fx.candidate_flash.programOpCount());
    f.command_flash.clearFault();
    ASSERT_TRUE(f.fx.integration.handleReceivedFrame(captured, sizeof(captured), 4));
    EXPECT_EQ(journal_writes, f.fx.candidate_flash.programOpCount());
    const auto erased = f.command_flash.eraseOpCount();
    ASSERT_TRUE(f.fx.integration.handleReceivedFrame(captured, sizeof(captured), 5));
    EXPECT_EQ(erased, f.command_flash.eraseOpCount());
    EXPECT_EQ(journal_writes, f.fx.candidate_flash.programOpCount());
    ASSERT_EQ(UsbOtaResult::Ok, f.fx.integration.leanReceiver().begin(
        f.owner.publicKey(), f.canonical, f.signature, true, false));
    ASSERT_EQ(UsbOtaResult::Ok, f.fx.integration.leanReceiver().putBlock(0, f.image.data(), 84));
    const auto fresh = f.fx.integration.leanReceiver().status();
    const auto running_reads = f.running.reads, command_reads = f.command_flash.readOpCount();
    const auto fresh_writes = f.fx.candidate_flash.programOpCount();
    EXPECT_FALSE(f.fx.integration.handleReceivedFrame(captured, sizeof(captured), 6));
    EXPECT_EQ(fresh.phase, f.fx.integration.leanReceiver().status().phase);
    EXPECT_EQ(fresh.generation, f.fx.integration.leanReceiver().status().generation);
    EXPECT_EQ(1u, f.fx.integration.leanReceiver().status().receivedBlocks);
    EXPECT_EQ(running_reads, f.running.reads);
    EXPECT_EQ(command_reads, f.command_flash.readOpCount());
    EXPECT_EQ(erased, f.command_flash.eraseOpCount());
    EXPECT_EQ(fresh_writes, f.fx.candidate_flash.programOpCount());
  }
}

TEST(LoraOtaLifecycle, ConsecutiveCompletedRollbacksPreserveBothCommandsAcrossAdminPrecommitAbortAndReupload) {
  using Phase = ::ota::storage::OtaCandidateStore::Phase;
  for (const uint32_t board : {0x584E3430u, 0x53435031u}) for (const uint8_t role : {0, 1}) {
    for (const auto phase : {Phase::Receiving, Phase::Verifying, Phase::Ready}) {
      SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << unsigned(phase));
      ConsecutiveRollbackFixture history(board, role); history.prepare(); ASSERT_FALSE(HasFatalFailure());
      auto& f = history.f;
      f.image[24] ^= 1; f.manifest(7);
      auto& receiver = f.fx.integration.leanReceiver();
      ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.begin(f.owner.publicKey(), f.canonical, f.signature, false, false));
      ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.putBlock(0, f.image.data(), 84));
      if (phase != Phase::Receiving) {
        ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.putBlock(1, f.image.data() + 84, 84));
        ASSERT_EQ(usb::UsbOtaResult::Pending, receiver.requestSeal());
        if (phase == Phase::Ready) receiver.loop();
      }
      ASSERT_EQ(phase, receiver.status().phase);
      const auto before = receiver.status();
      const auto commands = std::vector<uint8_t>(f.command_flash.rawBuffer(),
          f.command_flash.rawBuffer() + f.command_flash.rawSize());
      const auto image = std::vector<uint8_t>(f.fx.image_flash.rawBuffer(),
          f.fx.image_flash.rawBuffer() + f.fx.image_flash.rawSize());
      const auto floor = std::vector<uint8_t>(f.boot.floor_flash.rawBuffer(),
          f.boot.floor_flash.rawBuffer() + f.boot.floor_flash.rawSize());
      const auto states = std::vector<uint8_t>(f.boot.state_flash.rawBuffer(),
          f.boot.state_flash.rawBuffer() + f.boot.state_flash.rawSize());
      uint8_t seed[32] = {0xa7};
      ::ota::test::Ed25519TestSigner admin(seed);
      f.fx.admins.count = 0; f.fx.admins.add(admin.publicKey());
      uint8_t message[usb::kAbortSignedBytes], signature[64];
      usb::buildAbortSignedMessage(f.fx.target_public_key, before.imageHash, before.generation, message);
      admin.sign(message, sizeof(message), signature);
      ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(admin.publicKey(), signature, before.imageHash, before.generation));
      EXPECT_EQ(Phase::Aborted, receiver.status().phase);
      EXPECT_EQ(before.receivedBlocks, receiver.status().receivedBlocks);
      EXPECT_EQ(0, std::memcmp(before.ownerPublicKey, receiver.status().ownerPublicKey, 32));
      EXPECT_EQ(0, std::memcmp(image.data(), f.fx.image_flash.rawBuffer(), image.size()));
      EXPECT_EQ(0, std::memcmp(commands.data(), f.command_flash.rawBuffer(), commands.size()));
      EXPECT_EQ(0, std::memcmp(states.data(), f.boot.state_flash.rawBuffer(), states.size()));
      EXPECT_EQ(0, std::memcmp(floor.data(), f.boot.floor_flash.rawBuffer(), floor.size()));
      f.fx.integration = OtaFirmwareIntegration(); f.reattach(); f.fx.admins.add(admin.publicKey());
      auto& resumed = f.fx.integration.leanReceiver();
      uint8_t authorization[kOtaAuthorizationFrameBytes];
      const auto length = encodeOtaAuthorizationFrame(f.owner.publicKey(), f.canonical, f.signature,
                                                      authorization, sizeof(authorization));
      EXPECT_FALSE(f.fx.integration.handleReceivedFrame(authorization, length, 100));
      EXPECT_EQ(Phase::Aborted, resumed.status().phase);
      ASSERT_EQ(usb::UsbOtaResult::Ok, resumed.abort(admin.publicKey(), signature, before.imageHash, before.generation));
      f.image[36] ^= 1; f.manifest(8); admin.sign(f.canonical, sizeof(f.canonical), f.signature);
      ASSERT_EQ(usb::UsbOtaResult::Busy, resumed.begin(admin.publicKey(), f.canonical, f.signature, false, false));
      ASSERT_EQ(usb::UsbOtaResult::Ok, resumed.begin(admin.publicKey(), f.canonical, f.signature, true, false));
      for (uint16_t block = 0; block < 2; ++block)
        ASSERT_EQ(usb::UsbOtaResult::Ok, resumed.putBlock(block, f.image.data() + block * 84, 84));
      ASSERT_EQ(usb::UsbOtaResult::Pending, resumed.requestSeal()); resumed.loop();
      ASSERT_EQ(Phase::Ready, resumed.status().phase);
      EXPECT_EQ(0, std::memcmp(admin.publicKey(), resumed.status().ownerPublicKey, 32));
      EXPECT_EQ(0, std::memcmp(commands.data(), f.command_flash.rawBuffer(), commands.size()));
      EXPECT_EQ(0, std::memcmp(floor.data(), f.boot.floor_flash.rawBuffer(), floor.size()));
      if (phase == Phase::Ready) if (const char* directory = std::getenv("OTA_NRF_REMOTE_BOOT_PROOF_DIR")) {
        OtaNrf52RunningContext context; ASSERT_TRUE(f.running.read(context));
        const auto save = [&](const char* suffix, const uint8_t* bytes, size_t size) {
          char path[512];
          std::snprintf(path, sizeof(path), "%s/%08x-role%u-multi-rollback-%s.bin", directory,
                        static_cast<unsigned>(board), static_cast<unsigned>(role), suffix);
          FILE* output = std::fopen(path, "wb"); ASSERT_NE(nullptr, output);
          EXPECT_EQ(size, std::fwrite(bytes, 1, size, output)); EXPECT_EQ(0, std::fclose(output));
        };
        save("command-a", history.commands[0], sizeof(history.commands[0]));
        save("command-b", history.commands[1], sizeof(history.commands[1]));
        save("candidate-a", history.first_image.data(), history.first_image.size());
        save("candidate-b", history.second_image.data(), history.second_image.size());
        save("running", f.boot.accessor.image.data(), f.boot.accessor.image.size());
        save("sdk", context.settings, sizeof(context.settings));
        save("floor", floor.data(), floor.size());
        save("command-region", commands.data(), commands.size());
        save("next-candidate", f.image.data(), f.image.size());
        save("next-canonical", f.canonical, sizeof(f.canonical));
        ASSERT_FALSE(HasFatalFailure());
      }
    }
  }
}

TEST(LoraOtaLifecycle, ConsecutiveRollbackNoEraseProofUsesProductionSequenceWrapAndRefusesNewerTiedOrAmbiguousSibling) {
  struct Order { uint32_t a, b; bool allowed; };
  const Order orders[] = {{1, 2, true}, {0xfffffffe, 0xffffffff, true}, {0xffffffff, 0, true},
                          {2, 1, false}, {2, 2, false}, {1, 0x80000001, false},
                          {0x80000001, 1, false}, {1, 0x80000002, false}, {0x80000002, 1, true}};
  for (const auto order : orders) {
    SCOPED_TRACE(::testing::Message() << order.a << '/' << order.b);
    ConsecutiveRollbackFixture history; history.prepare(); ASSERT_FALSE(HasFatalFailure());
    auto& f = history.f;
    history.sequence(0, order.a); history.sequence(1, order.b); ASSERT_FALSE(HasFatalFailure());
    f.image[24] ^= 1; f.stage(7); ASSERT_FALSE(HasFatalFailure());
    const auto commands = std::vector<uint8_t>(f.command_flash.rawBuffer(),
        f.command_flash.rawBuffer() + f.command_flash.rawSize());
    const auto programs = f.fx.candidate_flash.programOpCount();
    EXPECT_EQ(order.allowed ? usb::UsbOtaResult::Ok : usb::UsbOtaResult::TooLate, f.abort());
    EXPECT_EQ(0, std::memcmp(commands.data(), f.command_flash.rawBuffer(), commands.size()));
    if (!order.allowed) EXPECT_EQ(programs, f.fx.candidate_flash.programOpCount());
  }
}

TEST(LoraOtaLifecycle, ConsecutiveRollbackProofNeverErasesNewerIntentOrIgnoresTornUnreadableAndActiveContext) {
  using Flash = ::ota::test::FakeNorFlash;
  for (int fault = 0; fault < 8; ++fault) {
    SCOPED_TRACE(fault);
    ConsecutiveRollbackFixture history; history.prepare(); ASSERT_FALSE(HasFatalFailure());
    auto& f = history.f;
    f.image[24] ^= 1; f.stage(7); ASSERT_FALSE(HasFatalFailure());
    if (fault == 0) f.command_flash.armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before,
                                             f.command_flash.readOpCount() + 18});
    if (fault == 1) {
      const uint8_t zero = 0; ASSERT_TRUE(::ota::platform::isOk(f.command.program(4096, &zero, 1)));
    }
    if (fault == 2 || fault == 3) {
      ASSERT_TRUE(::ota::platform::isOk(f.boot.state.eraseSector(0)));
      if (fault == 2) f.boot.setState(::ota::storage::XiaoOtaStateReader::kPhaseTrialBoot, 6,
          ::ota::storage::XiaoOtaCommandRecordV3::transactionNonceOf(history.commands[1]));
    }
    if (fault == 4) f.running.bank1 = 1;
    if (fault == 5) f.boot.accessor.image.back() ^= 1;
    if (fault >= 6) {
      const auto ready = f.fx.integration.leanReceiver().status();
      uint8_t message[usb::kCommitSignedBytes], signature[64];
      usb::buildCommitSignedMessage(f.fx.target_public_key, ready.manifestHash, ready.counter, message);
      f.owner.sign(message, sizeof(message), signature);
      f.fx.candidate_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Before,
                                    f.fx.candidate_flash.programOpCount() + 1});
      ASSERT_EQ(usb::UsbOtaResult::IoError, f.fx.integration.leanReceiver().commit(ready.counter, signature));
      f.fx.candidate_flash.clearFault();
      if (fault == 7) {
        ::ota::storage::OtaCandidateStore::Snapshot aborted; ASSERT_TRUE(f.fx.candidate_store.load(aborted));
        aborted.phase = ::ota::storage::OtaCandidateStore::Phase::Aborted; ++aborted.sessionId;
        ASSERT_TRUE(f.fx.candidate_store.append(aborted));
      }
      f.fx.integration = OtaFirmwareIntegration(); f.reattach();
      const uint8_t zero = 0; ASSERT_TRUE(::ota::platform::isOk(f.fx.image_region.program(16, &zero, 1)));
    }
    const auto writes = f.fx.candidate_flash.programOpCount(), erases = f.command_flash.eraseOpCount();
    const auto before = f.fx.integration.leanReceiver().status();
    EXPECT_EQ(fault == 0 ? usb::UsbOtaResult::IoError : usb::UsbOtaResult::TooLate, f.abort());
    EXPECT_EQ(writes, f.fx.candidate_flash.programOpCount()); EXPECT_EQ(erases, f.command_flash.eraseOpCount());
    EXPECT_EQ(before.phase, f.fx.integration.leanReceiver().status().phase);
    EXPECT_EQ(before.receivedBlocks, f.fx.integration.leanReceiver().status().receivedBlocks);
  }
}

TEST(LoraOtaLifecycle, CompletedRollbackDoesNotBlockAnotherAdminAbortingNewReceivingVerifyingOrReadyCandidate) {
  using Phase = ::ota::storage::OtaCandidateStore::Phase;
  for (const uint32_t board : {0x584E3430u, 0x53435031u}) for (const uint8_t role : {0, 1}) {
    for (const auto phase : {Phase::Receiving, Phase::Verifying, Phase::Ready}) {
      SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << unsigned(phase));
      UnadmittedFixture f(board, role);
      const auto previous_image = f.image;
      f.recordCompletedRollback(); ASSERT_FALSE(HasFatalFailure());
      uint8_t previous_command[::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes];
      ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(f.command, previous_command));
      f.image[12] ^= 1; f.manifest(6);
      auto& receiver = f.fx.integration.leanReceiver();
      ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.begin(f.owner.publicKey(), f.canonical, f.signature, false, false));
      ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.putBlock(0, f.image.data(), 84));
      if (phase != Phase::Receiving) {
        ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.putBlock(1, f.image.data() + 84, 84));
        ASSERT_EQ(usb::UsbOtaResult::Pending, receiver.requestSeal());
        if (phase == Phase::Ready) receiver.loop();
      }
      ASSERT_EQ(phase, receiver.status().phase);
      const auto before = receiver.status();
      const auto bytes = std::vector<uint8_t>(f.fx.image_flash.rawBuffer(),
          f.fx.image_flash.rawBuffer() + f.fx.image_flash.rawSize());
      const auto commands = std::vector<uint8_t>(f.command_flash.rawBuffer(),
          f.command_flash.rawBuffer() + f.command_flash.rawSize());
      const auto states = std::vector<uint8_t>(f.boot.state_flash.rawBuffer(),
          f.boot.state_flash.rawBuffer() + f.boot.state_flash.rawSize());
      const auto floor = std::vector<uint8_t>(f.boot.floor_flash.rawBuffer(),
          f.boot.floor_flash.rawBuffer() + f.boot.floor_flash.rawSize());
      uint8_t seed[32] = {0xa6};
      ::ota::test::Ed25519TestSigner admin(seed);
      f.fx.admins.count = 0; f.fx.admins.add(admin.publicKey());
      uint8_t message[usb::kAbortSignedBytes], signature[64];
      usb::buildAbortSignedMessage(f.fx.target_public_key, before.imageHash, before.generation, message);
      admin.sign(message, sizeof(message), signature);
      ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.abort(admin.publicKey(), signature, before.imageHash, before.generation));
      EXPECT_EQ(Phase::Aborted, receiver.status().phase);
      EXPECT_EQ(before.receivedBlocks, receiver.status().receivedBlocks);
      EXPECT_EQ(0, std::memcmp(before.ownerPublicKey, receiver.status().ownerPublicKey, 32));
      EXPECT_EQ(0, std::memcmp(bytes.data(), f.fx.image_flash.rawBuffer(), bytes.size()));
      EXPECT_EQ(0, std::memcmp(commands.data(), f.command_flash.rawBuffer(), commands.size()));
      EXPECT_EQ(0, std::memcmp(states.data(), f.boot.state_flash.rawBuffer(), states.size()));
      EXPECT_EQ(0, std::memcmp(floor.data(), f.boot.floor_flash.rawBuffer(), floor.size()));

      f.fx.integration = OtaFirmwareIntegration(); f.reattach();
      f.fx.admins.add(admin.publicKey());
      auto& resumed = f.fx.integration.leanReceiver();
      uint8_t authorization[kOtaAuthorizationFrameBytes];
      const auto authorization_size = encodeOtaAuthorizationFrame(f.owner.publicKey(), f.canonical, f.signature,
                                                                  authorization, sizeof(authorization));
      EXPECT_FALSE(f.fx.integration.handleReceivedFrame(authorization, authorization_size, 100));
      EXPECT_EQ(usb::UsbOtaResult::BadRequest, resumed.putBlock(1, f.image.data() + 84, 84));
      EXPECT_EQ(Phase::Aborted, resumed.status().phase);
      EXPECT_EQ(0, std::memcmp(bytes.data(), f.fx.image_flash.rawBuffer(), bytes.size()));
      uint8_t abort_frame[kOtaAbortFrameBytes];
      const auto abort_size = encodeOtaAbortFrame(admin.publicKey(), f.fx.target_public_key, before.imageHash,
                                                before.generation, signature, abort_frame, sizeof(abort_frame));
      ASSERT_TRUE(f.fx.integration.handleReceivedFrame(abort_frame, abort_size, 101));
      f.image[24] ^= 1; f.manifest(7);
      admin.sign(f.canonical, sizeof(f.canonical), f.signature);
      ASSERT_EQ(usb::UsbOtaResult::Busy, resumed.begin(admin.publicKey(), f.canonical, f.signature, false, false));
      ASSERT_EQ(usb::UsbOtaResult::Ok, resumed.begin(admin.publicKey(), f.canonical, f.signature, true, false));
      for (uint16_t block = 0; block < 2; ++block)
        ASSERT_EQ(usb::UsbOtaResult::Ok, resumed.putBlock(block, f.image.data() + block * 84, 84));
      ASSERT_EQ(usb::UsbOtaResult::Pending, resumed.requestSeal()); resumed.loop();
      ASSERT_EQ(Phase::Ready, resumed.status().phase);
      EXPECT_EQ(0, std::memcmp(admin.publicKey(), resumed.status().ownerPublicKey, 32));
      EXPECT_EQ(0, std::memcmp(commands.data(), f.command_flash.rawBuffer(), commands.size()));
      EXPECT_EQ(0, std::memcmp(floor.data(), f.boot.floor_flash.rawBuffer(), floor.size()));
      if (phase == Phase::Ready) if (const char* directory = std::getenv("OTA_NRF_REMOTE_BOOT_PROOF_DIR")) {
        OtaNrf52RunningContext context; ASSERT_TRUE(f.running.read(context));
        const auto save = [&](const char* suffix, const uint8_t* data, size_t size) {
          char path[512];
          std::snprintf(path, sizeof(path), "%s/%08x-role%u-rollback-%s.bin", directory,
                        static_cast<unsigned>(board), static_cast<unsigned>(role), suffix);
          FILE* output = std::fopen(path, "wb");
          ASSERT_NE(nullptr, output);
          EXPECT_EQ(size, std::fwrite(data, 1, size, output));
          EXPECT_EQ(0, std::fclose(output));
        };
        save("command", previous_command, sizeof(previous_command));
        save("candidate", previous_image.data(), previous_image.size());
        save("running", f.boot.accessor.image.data(), f.boot.accessor.image.size());
        save("sdk", context.settings, sizeof(context.settings));
        save("floor", floor.data(), floor.size());
        save("next-candidate", f.image.data(), f.image.size());
        save("next-canonical", f.canonical, sizeof(f.canonical));
        save("retained-command-region", commands.data(), commands.size());
        ASSERT_FALSE(HasFatalFailure());
      }
    }
  }
}

TEST(LoraOtaLifecycle, CompletedRollbackPrecommitAbortStillRefusesUnboundUncertainMalformedAndIoContexts) {
  using Flash = ::ota::test::FakeNorFlash;
  for (int fault = 0; fault < 18; ++fault) {
    SCOPED_TRACE(fault);
    UnadmittedFixture f; f.recordCompletedRollback(); ASSERT_FALSE(HasFatalFailure());
    f.image[12] ^= 1; f.stage(6); ASSERT_FALSE(HasFatalFailure());
    const auto before = f.fx.integration.leanReceiver().status();
    if (fault < 3) {
      auto* flash = fault == 0 ? &f.command_flash : fault == 1 ? &f.boot.state_flash : &f.boot.floor_flash;
      flash->armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before, flash->readOpCount() + 1});
    }
    if (fault == 3) f.running.fail = true;
    if (fault == 4) f.running.bank1 = 1;
    if (fault == 5) f.running.bank1 = 0xffff;
    if (fault == 6) f.running.invalid = true;
    if (fault == 7) f.running.badCrc = true;
    if (fault == 8) {
      const uint8_t zero = 0;
      ASSERT_TRUE(::ota::platform::isOk(f.command.program(0, &zero, 1)));
    }
    if (fault >= 9 && fault <= 13) {
      ASSERT_TRUE(::ota::platform::isOk(f.boot.state.eraseSector(0)));
      const auto phase = fault == 9 ? ::ota::storage::XiaoOtaStateReader::kPhaseTrialBoot :
                                     ::ota::storage::XiaoOtaStateReader::kPhaseFailedMax;
      uint8_t candidate_hash[32];
      std::memcpy(candidate_hash, ::ota::storage::XiaoOtaCommandRecordV3::wireDescriptorOf(
          f.command_flash.rawBuffer()) + 13, sizeof(candidate_hash));
      if (fault == 12) candidate_hash[0] ^= 1;
      f.boot.setState(phase, fault == 11 ? 6 : 5, fault == 10 ? 17 :
          ::ota::storage::XiaoOtaCommandRecordV3::transactionNonceOf(f.command_flash.rawBuffer()),
          candidate_hash, f.boot.hash, f.boot.accessor.image.size() + (fault == 13 ? 1 : 0));
    }
    if (fault == 14) f.boot.accessor.image.back() ^= 1;
    if (fault == 15) f.running.tailErased = false;
    if (fault == 16) ASSERT_TRUE(::ota::platform::isOk(f.boot.state.eraseSector(0)));
    if (fault == 17) {
      const uint8_t zero = 0;
      ASSERT_TRUE(::ota::platform::isOk(f.boot.state.program(4095, &zero, 1)));
    }
    const auto writes = f.fx.candidate_flash.programOpCount();
    const auto erases = f.command_flash.eraseOpCount();
    EXPECT_EQ(fault < 4 ? usb::UsbOtaResult::IoError : usb::UsbOtaResult::TooLate, f.abort());
    EXPECT_EQ(writes, f.fx.candidate_flash.programOpCount());
    EXPECT_EQ(erases, f.command_flash.eraseOpCount());
    EXPECT_EQ(before.phase, f.fx.integration.leanReceiver().status().phase);
    EXPECT_EQ(before.receivedBlocks, f.fx.integration.leanReceiver().status().receivedBlocks);
    EXPECT_EQ(0, std::memcmp(before.ownerPublicKey, f.fx.integration.leanReceiver().status().ownerPublicKey, 32));
  }
}

TEST(LoraOtaLifecycle, ReadyUncertainCommitStillDisarmsOnlyBoundIntentAndNeverLeavesConsumedAboveFloorSibling) {
  for (const bool rollback_sibling : {false, true}) {
    UnadmittedFixture f;
    if (rollback_sibling) { f.recordCompletedRollback(); f.image[12] ^= 1; }
    f.stage(rollback_sibling ? 6 : 5); ASSERT_FALSE(HasFatalFailure());
    const auto ready = f.fx.integration.leanReceiver().status();
    uint8_t message[usb::kCommitSignedBytes], signature[64];
    usb::buildCommitSignedMessage(f.fx.target_public_key, ready.manifestHash, ready.counter, message);
    f.owner.sign(message, sizeof(message), signature);
    f.fx.candidate_flash.armFault({::ota::test::FakeNorFlash::OpKind::Program,
        ::ota::test::FakeNorFlash::InjectionTiming::Before, f.fx.candidate_flash.programOpCount() + 1});
    EXPECT_EQ(usb::UsbOtaResult::IoError, f.fx.integration.leanReceiver().commit(ready.counter, signature));
    f.fx.candidate_flash.clearFault();
    f.fx.integration = OtaFirmwareIntegration(); f.reattach();
    const uint8_t zero = 0;
    ASSERT_TRUE(::ota::platform::isOk(f.fx.image_region.program(16, &zero, 1)));
    const auto erases = f.command_flash.eraseOpCount();
    EXPECT_EQ(rollback_sibling ? usb::UsbOtaResult::TooLate : usb::UsbOtaResult::Ok, f.abort());
    EXPECT_EQ(rollback_sibling ? erases : erases + 1, f.command_flash.eraseOpCount());
    EXPECT_EQ(rollback_sibling ? ::ota::storage::OtaCandidateStore::Phase::Ready :
                                ::ota::storage::OtaCandidateStore::Phase::Aborted,
              f.fx.integration.leanReceiver().status().phase);
  }
}

TEST(LoraOtaLifecycle, ProductionUnadmittedNrfCommandAfterValidUsbReflashNeedsExplicitSignedAbortBeforeNextCampaign) {
  for (const uint32_t board : {0x584E3430u, 0x53435031u}) for (const uint8_t role : {0, 1}) {
    UnadmittedFixture f(board, role);
    f.stage(); ASSERT_FALSE(HasFatalFailure()); f.commit(); ASSERT_FALSE(HasFatalFailure());
    const auto committed = f.fx.integration.leanReceiver().status();
    const auto candidate_bytes = std::vector<uint8_t>(f.fx.image_flash.rawBuffer(),
        f.fx.image_flash.rawBuffer() + f.fx.image_flash.rawSize());
    const auto floor_bytes = std::vector<uint8_t>(f.boot.floor_flash.rawBuffer(),
        f.boot.floor_flash.rawBuffer() + f.boot.floor_flash.rawSize());
    uint8_t command[::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes];
    ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(f.command, command));
    EXPECT_EQ(committed.transactionNonce, ::ota::storage::XiaoOtaCommandRecordV3::transactionNonceOf(command));
    EXPECT_EQ(usb::UsbOtaResult::TooLate, f.abort());
    f.boot.accessor.image.back() ^= 0x42;  // New USB image and fresh valid SDK bank0 CRC.
    f.fx.integration = OtaFirmwareIntegration();
    f.reattach();
    EXPECT_EQ(usb::UsbOtaPhase::CommitPending, f.fx.integration.reportedPhase());
    const auto erases = f.fx.image_flash.eraseOpCount();
    f.image[12] ^= 1; f.manifest(6);
    EXPECT_EQ(usb::UsbOtaResult::Busy, f.fx.integration.leanReceiver().begin(
        f.owner.publicKey(), f.canonical, f.signature, true, false));
    EXPECT_EQ(erases, f.fx.image_flash.eraseOpCount());
    EXPECT_EQ(usb::UsbOtaResult::Ok, f.abort());
    EXPECT_FALSE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(f.command, command));
    EXPECT_EQ(committed.counter, f.fx.integration.leanReceiver().status().counter);
    EXPECT_EQ(0, std::memcmp(candidate_bytes.data(), f.fx.image_flash.rawBuffer(), candidate_bytes.size()));
    EXPECT_EQ(0, std::memcmp(floor_bytes.data(), f.boot.floor_flash.rawBuffer(), floor_bytes.size()));
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, f.fx.integration.leanReceiver().status().phase);
    f.stage(6, true); ASSERT_FALSE(HasFatalFailure()); f.commit(); ASSERT_FALSE(HasFatalFailure());
    ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(f.command, command));
    EXPECT_NE(committed.transactionNonce, ::ota::storage::XiaoOtaCommandRecordV3::transactionNonceOf(command));
    OtaNrf52RunningContext context; ASSERT_TRUE(f.running.read(context));
    const auto actual = ::ota::storage::XiaoOtaActiveExtentBridge::resolve(
        ::ota::storage::XiaoOtaActiveExtentBridge::decodeBank0FromRaw28Bytes(context.settings), context.image, context.capacity);
    EXPECT_EQ(0, std::memcmp(actual.active_image_hash_sha256,
        ::ota::storage::XiaoOtaCommandRecordV3::activeImageHashOf(command), 32));
  }
}

TEST(LoraOtaLifecycle, UnadmittedRecoveryRefusesActiveTrialCopyInvalidSdkUnknownAndUnboundCommandWithoutMutation) {
  for (int fault = 0; fault < 21; ++fault) {
    SCOPED_TRACE(fault);
    UnadmittedFixture f; f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
    f.boot.accessor.image.back() ^= 1;
    if (fault < 5) f.boot.setState(fault == 4 ? 7 : fault + 1, 5, 17);
    if (fault == 5) f.running.invalid = true;
    if (fault == 6) f.running.badCrc = true;
    if (fault == 7) f.running.bank1 = 1;
    if (fault == 8) f.running.bank1 = 0xffff;
    if (fault == 9) f.running.fail = true;
    if (fault == 10) f.qualified = false;
    if (fault == 11) ASSERT_TRUE(::ota::platform::isOk(f.command.eraseSector(0)));
    if (fault == 12) { const uint8_t zero = 0; ASSERT_TRUE(::ota::platform::isOk(f.command.program(0, &zero, 1))); }
    ::ota::test::FakeNorFlash* failing = nullptr;
    if (fault == 13) failing = &f.command_flash;
    if (fault == 14) failing = &f.boot.state_flash;
    if (fault == 15) failing = &f.boot.floor_flash;
    if (failing) failing->armFault({::ota::test::FakeNorFlash::OpKind::Read,
        ::ota::test::FakeNorFlash::InjectionTiming::Before, failing->readOpCount() + 1});
    if (fault == 16) f.boot.setState(::ota::storage::XiaoOtaStateReader::kPhaseConfirmed, 5,
                                    f.fx.integration.leanReceiver().status().transactionNonce);
    if (fault == 17) f.boot.setState(::ota::storage::XiaoOtaStateReader::kPhaseTrialBoot, 5, 17);
    if (fault == 18) f.running.bank1 = 0xa5;
    if (fault == 19) f.running.bank1 = 0xaa;
    if (fault == 20) f.boot.setState(::ota::storage::XiaoOtaStateReader::kPhaseConfirmed, 6, 17);
    const auto writes = f.fx.candidate_flash.programOpCount();
    const auto erases = f.command_flash.eraseOpCount();
    EXPECT_NE(usb::UsbOtaResult::Ok, f.abort());
    EXPECT_EQ(writes, f.fx.candidate_flash.programOpCount());
    EXPECT_EQ(erases, f.command_flash.eraseOpCount());
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, f.fx.integration.leanReceiver().status().phase);
  }
}

TEST(LoraOtaLifecycle, ProvenQspiHashAndPolicyRefusalsStillRequireExplicitAbortAndDoNotRewriteImageOrFloor) {
  for (int refusal = 0; refusal < 3; ++refusal) {
    UnadmittedFixture f; f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
    if (refusal == 0) { const uint8_t zero = 0; ASSERT_TRUE(::ota::platform::isOk(f.fx.image_region.program(16, &zero, 1))); }
    if (refusal == 1) f.boot.setFloor(5);
    if (refusal == 2) f.running.tailErased = false;
    const auto programs = f.fx.image_flash.programOpCount();
    const auto erases = f.fx.image_flash.eraseOpCount();
    const auto floor_programs = f.boot.floor_flash.programOpCount();
    EXPECT_EQ(usb::UsbOtaResult::Ok, f.abort());
    EXPECT_EQ(programs, f.fx.image_flash.programOpCount());
    EXPECT_EQ(erases, f.fx.image_flash.eraseOpCount());
    EXPECT_EQ(floor_programs, f.boot.floor_flash.programOpCount());
    if (refusal == 1) {
      f.reattach();
      const auto metadata_erases = f.fx.candidate_flash.eraseOpCount();
      f.manifest(5);
      EXPECT_EQ(usb::UsbOtaResult::Denied, f.fx.integration.leanReceiver().begin(
          f.owner.publicKey(), f.canonical, f.signature, true, false));
      EXPECT_EQ(metadata_erases, f.fx.candidate_flash.eraseOpCount());
    }
  }
}

TEST(LoraOtaLifecycle, DurableUnadmittedAbortSurvivesCancellationErrorAndRebootBeforeAuthorizedReupload) {
  for (const auto timing : {::ota::test::FakeNorFlash::InjectionTiming::Before,
                            ::ota::test::FakeNorFlash::InjectionTiming::After}) {
    UnadmittedFixture f; f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
    f.boot.accessor.image.back() ^= 1;
    f.command_flash.armFault({::ota::test::FakeNorFlash::OpKind::Erase, timing, f.command_flash.eraseOpCount() + 1});
    EXPECT_EQ(usb::UsbOtaResult::IoError, f.abort());
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, f.fx.integration.leanReceiver().status().phase);
    f.command_flash.clearFault();
    f.fx.integration = OtaFirmwareIntegration();
    f.reattach();
    f.image[12] ^= 1;
    f.stage(6, true); ASSERT_FALSE(HasFatalFailure()); f.commit();
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, f.fx.integration.leanReceiver().status().phase);
  }
}

TEST(LoraOtaLifecycle, PreviousConfirmedStateAndOriginalOwnerRevocationDoNotBecomeFloorOnlyOrUnsignedRecovery) {
  UnadmittedFixture f;
  f.boot.setState(::ota::storage::XiaoOtaStateReader::kPhaseConfirmed, 4, 17);
  f.boot.setFloor(4);
  f.reattach();
  f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
  f.boot.accessor.image.back() ^= 1;
  f.fx.admins.count = 0;
  EXPECT_EQ(usb::UsbOtaResult::Denied, f.abort());
  uint8_t seed[32] = {0x84};
  ::ota::test::Ed25519TestSigner admin(seed);
  f.fx.admins.add(admin.publicKey());
  const auto before = f.fx.integration.leanReceiver().status();
  uint8_t message[usb::kAbortSignedBytes], sig[64];
  usb::buildAbortSignedMessage(f.fx.target_public_key, before.imageHash, before.generation, message);
  admin.sign(message, sizeof(message), sig);
  EXPECT_EQ(usb::UsbOtaResult::Ok,
            f.fx.integration.leanReceiver().abort(admin.publicKey(), sig, before.imageHash, before.generation));
  EXPECT_EQ(0, std::memcmp(before.ownerPublicKey, f.fx.integration.leanReceiver().status().ownerPublicKey, 32));
  uint32_t floor = 0;
  ASSERT_TRUE(::ota::storage::XiaoOtaFloorReader::readNewestConfirmedCounterFailClosed(f.boot.floor, floor));
  EXPECT_EQ(4u, floor);
}

TEST(LoraOtaLifecycle, RefusedCommandIsNotCancelledUntilAbortJournalAcknowledgesAndTornCommandRemainsConservative) {
  for (const bool torn_command : {false, true}) {
    UnadmittedFixture f; f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
    f.boot.accessor.image.back() ^= 1;
    if (!torn_command) {
      f.fx.candidate_flash.armFault({::ota::test::FakeNorFlash::OpKind::Program,
          ::ota::test::FakeNorFlash::InjectionTiming::Before, f.fx.candidate_flash.programOpCount() + 1});
      const auto erases = f.command_flash.eraseOpCount();
      EXPECT_EQ(usb::UsbOtaResult::IoError, f.abort());
      EXPECT_EQ(erases, f.command_flash.eraseOpCount());
      EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, f.fx.integration.leanReceiver().status().phase);
      f.fx.candidate_flash.clearFault();
      EXPECT_EQ(usb::UsbOtaResult::Ok, f.abort());
    } else {
      f.command_flash.armFault({::ota::test::FakeNorFlash::OpKind::Erase,
          ::ota::test::FakeNorFlash::InjectionTiming::Mid, f.command_flash.eraseOpCount() + 1, 32});
      EXPECT_EQ(usb::UsbOtaResult::IoError, f.abort());
      f.command_flash.clearFault();
      f.fx.integration = OtaFirmwareIntegration(); f.reattach();
      f.image[12] ^= 1; f.manifest(6);
      const auto erases = f.fx.image_flash.eraseOpCount();
      EXPECT_EQ(usb::UsbOtaResult::TooLate, f.fx.integration.leanReceiver().begin(
          f.owner.publicKey(), f.canonical, f.signature, true, false));
      EXPECT_EQ(erases, f.fx.image_flash.eraseOpCount());
      EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, f.fx.integration.leanReceiver().status().phase);
    }
  }
}

TEST(LoraOtaLifecycle, UnadmittedRecoveryChecksExactCommandBindingAndStableWholeRunningProof) {
  using Cmd = ::ota::storage::XiaoOtaCommandRecordV3;
  for (int fault = 0; fault < 5; ++fault) {
    UnadmittedFixture f; f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
    f.boot.accessor.image.back() ^= 1;
    uint32_t offset = Cmd::isValidRecord(f.command_flash.rawBuffer(), Cmd::kRecordBytes) ? 0 : 4096;
    uint8_t record[Cmd::kRecordBytes];
    ASSERT_TRUE(::ota::platform::isOk(f.command.read(offset, record, sizeof(record))));
    if (fault == 0) record[12] ^= 1;
    if (fault == 1) {
      record[20 + 48] = 6;
      f.owner.sign(record + 20, 59, record + Cmd::kSignatureOffset);
    }
    if (fault == 2) {
      uint8_t seed[32] = {0x85};
      ::ota::test::Ed25519TestSigner other(seed);
      std::memcpy(record + 79, other.publicKey(), 32);
      other.sign(record + 20, 59, record + Cmd::kSignatureOffset);
    }
    LifecycleFixture::le32(record + Cmd::kCrcOffset,
        ::ota::storage::Crc32::computeFinalized(record, Cmd::kCrcOffset));
    ASSERT_TRUE(::ota::platform::isOk(f.command.eraseSector(offset)));
    ASSERT_TRUE(::ota::platform::isOk(f.command.program(offset, record, sizeof(record))));
    if (fault == 3) f.running.failAt = 2;
    if (fault == 4) f.running.changeAt = 2;
    const auto command_erases = f.command_flash.eraseOpCount();
    const auto journal_writes = f.fx.candidate_flash.programOpCount();
    EXPECT_EQ(fault == 3 ? usb::UsbOtaResult::IoError : usb::UsbOtaResult::TooLate, f.abort());
    EXPECT_EQ(command_erases, f.command_flash.eraseOpCount());
    EXPECT_EQ(journal_writes, f.fx.candidate_flash.programOpCount());
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, f.fx.integration.leanReceiver().status().phase);
  }
}

TEST(LoraOtaLifecycle, UnadmittedRecoveryRejectsAdmissibleSiblingAndCancelsOlderDuplicateBeforeNewest) {
  using Cmd = ::ota::storage::XiaoOtaCommandRecordV3;
  for (const bool admissible_sibling : {false, true}) {
    UnadmittedFixture f; f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
    f.boot.accessor.image.back() ^= 1;
    const uint8_t* newest = f.command_flash.rawBuffer();
    uint32_t sibling_offset = 4096;
    if (!Cmd::isValidRecord(newest, Cmd::kRecordBytes)) {
      newest += 4096; sibling_offset = 0;
    }
    uint8_t sibling[Cmd::kRecordBytes];
    std::memcpy(sibling, newest, sizeof(sibling));
    LifecycleFixture::le32(sibling + 8, Cmd::sequenceOf(newest) - 1);
    if (admissible_sibling) {
      sibling[12] ^= 1;
      ::ota::trust::Sha256::hash(f.boot.accessor.image.data(), f.boot.accessor.image.size(),
                               sibling + Cmd::kActiveExtentOffset + 4);
    }
    LifecycleFixture::le32(sibling + Cmd::kCrcOffset,
        ::ota::storage::Crc32::computeFinalized(sibling, Cmd::kCrcOffset));
    ASSERT_TRUE(::ota::platform::isOk(f.command.program(sibling_offset, sibling, sizeof(sibling))));
    const auto erases = f.command_flash.eraseOpCount();
    if (admissible_sibling) {
      EXPECT_EQ(usb::UsbOtaResult::TooLate, f.abort());
      EXPECT_EQ(erases, f.command_flash.eraseOpCount());
    } else {
      f.command_flash.armFault({::ota::test::FakeNorFlash::OpKind::Erase,
          ::ota::test::FakeNorFlash::InjectionTiming::Before, erases + 2});
      EXPECT_EQ(usb::UsbOtaResult::IoError, f.abort());
      EXPECT_TRUE(Cmd::isValidRecord(newest, Cmd::kRecordBytes));
      f.command_flash.clearFault();
      EXPECT_EQ(usb::UsbOtaResult::Ok, f.abort());
      uint8_t remaining[Cmd::kRecordBytes];
      EXPECT_FALSE(Cmd::readNewest(f.command, remaining));
    }
  }
}

TEST(LoraOtaLifecycle, UnadmittedRecoveryNeverLeavesAnUnboundSiblingAboveTheProtectedFloor) {
  using Cmd = ::ota::storage::XiaoOtaCommandRecordV3;
  for (const uint32_t sibling_counter : {4u, 5u, 6u}) {
    SCOPED_TRACE(sibling_counter);
    UnadmittedFixture f;
    f.boot.setFloor(4); f.reattach(); f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
    const auto old_running = f.boot.accessor.image;
    f.boot.accessor.image.back() ^= 1;
    uint8_t latest[Cmd::kRecordBytes], sibling[Cmd::kRecordBytes];
    ASSERT_TRUE(Cmd::readNewest(f.command, latest));
    std::memcpy(sibling, latest, sizeof(sibling));
    LifecycleFixture::le32(sibling + 8, Cmd::sequenceOf(latest) - 1);
    sibling[12] ^= 1;
    usb::putBE32(sibling + 20 + 45, sibling_counter);
    f.owner.sign(sibling + 20, 59, sibling + Cmd::kSignatureOffset);
    LifecycleFixture::le32(sibling + Cmd::kCrcOffset,
        ::ota::storage::Crc32::computeFinalized(sibling, Cmd::kCrcOffset));
    const uint32_t sibling_offset = Cmd::isValidRecord(f.command_flash.rawBuffer(), Cmd::kRecordBytes) ? 4096 : 0;
    ASSERT_TRUE(::ota::platform::isOk(f.command.program(sibling_offset, sibling, sizeof(sibling))));
    ::ota::storage::OtaCandidateStore::Snapshot durable;
    ASSERT_TRUE(f.fx.candidate_store.load(durable));
    const auto image_before = std::vector<uint8_t>(f.fx.image_flash.rawBuffer(),
        f.fx.image_flash.rawBuffer() + f.fx.image_flash.rawSize());
    const auto command_before = std::vector<uint8_t>(f.command_flash.rawBuffer(),
        f.command_flash.rawBuffer() + f.command_flash.rawSize());
    const auto journal_programs = f.fx.candidate_flash.programOpCount();
    const auto command_erases = f.command_flash.eraseOpCount();
    const auto state_programs = f.boot.state_flash.programOpCount();
    const auto floor_programs = f.boot.floor_flash.programOpCount();
    const auto expected = sibling_counter <= 4 ? usb::UsbOtaResult::Ok : usb::UsbOtaResult::TooLate;
    EXPECT_EQ(expected, f.recovery.recover(durable, false));
    EXPECT_EQ(journal_programs, f.fx.candidate_flash.programOpCount());
    EXPECT_EQ(command_erases, f.command_flash.eraseOpCount());
    EXPECT_EQ(0, std::memcmp(command_before.data(), f.command_flash.rawBuffer(), command_before.size()));
    EXPECT_EQ(expected, f.abort());
    EXPECT_EQ(state_programs, f.boot.state_flash.programOpCount());
    EXPECT_EQ(floor_programs, f.boot.floor_flash.programOpCount());
    EXPECT_EQ(0, std::memcmp(image_before.data(), f.fx.image_flash.rawBuffer(), image_before.size()));
    if (sibling_counter > 4) {
      EXPECT_EQ(journal_programs, f.fx.candidate_flash.programOpCount());
      EXPECT_EQ(command_erases, f.command_flash.eraseOpCount());
      EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, f.fx.integration.leanReceiver().status().phase);
      f.manifest(6);
      const auto image_erases = f.fx.image_flash.eraseOpCount();
      EXPECT_EQ(usb::UsbOtaResult::TooLate, f.fx.integration.leanReceiver().begin(
          f.owner.publicKey(), f.canonical, f.signature, true, false));
      EXPECT_EQ(image_erases, f.fx.image_flash.eraseOpCount());
    } else {
      // The surviving older command is permanently below the protected floor.
      EXPECT_TRUE(Cmd::isValidRecord(f.command_flash.rawBuffer() + sibling_offset, Cmd::kRecordBytes));
      f.boot.accessor.image = old_running;
      f.stage(6, true); ASSERT_FALSE(HasFatalFailure());
      EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, f.fx.integration.leanReceiver().status().phase);
      EXPECT_EQ(4u, sibling_counter);
    }
  }
}

TEST(LoraOtaLifecycle, RefusedCommitIsDurablyDisarmedBeforeSameBytesNewCounterReachReadyWithoutCommit) {
  using Cmd = ::ota::storage::XiaoOtaCommandRecordV3;
  for (const uint32_t board : {0x584E3430u, 0x53435031u}) for (const uint8_t role : {0, 1}) {
    UnadmittedFixture f(board, role);
    ::ota::trust::Sha256::hash(f.boot.accessor.image.data(), f.boot.accessor.image.size(), f.boot.hash);
    f.boot.setFloor(4); f.reattach(); f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
    const auto original = f.fx.integration.leanReceiver().status();
    const auto old_running = f.boot.accessor.image;
    uint8_t command[Cmd::kRecordBytes], duplicate[Cmd::kRecordBytes];
    ASSERT_TRUE(Cmd::readNewest(f.command, command));
    std::memcpy(duplicate, command, sizeof(duplicate));
    LifecycleFixture::le32(duplicate + 8, Cmd::sequenceOf(command) - 1);
    LifecycleFixture::le32(duplicate + Cmd::kCrcOffset,
        ::ota::storage::Crc32::computeFinalized(duplicate, Cmd::kCrcOffset));
    const uint32_t duplicate_offset = Cmd::isValidRecord(f.command_flash.rawBuffer(), Cmd::kRecordBytes) ? 4096 : 0;
    ASSERT_TRUE(::ota::platform::isOk(f.command.program(duplicate_offset, duplicate, sizeof(duplicate))));
    f.boot.accessor.image.back() ^= 0x42;
    const auto image_programs = f.fx.image_flash.programOpCount();
    const auto image_erases = f.fx.image_flash.eraseOpCount();
    const auto state_programs = f.boot.state_flash.programOpCount();
    const auto floor_programs = f.boot.floor_flash.programOpCount();
    const auto command_erases = f.command_flash.eraseOpCount();
    EXPECT_EQ(usb::UsbOtaResult::Ok, f.abort());
    EXPECT_EQ(command_erases + 2, f.command_flash.eraseOpCount());
    EXPECT_EQ(image_programs, f.fx.image_flash.programOpCount());
    EXPECT_EQ(image_erases, f.fx.image_flash.eraseOpCount());
    EXPECT_EQ(state_programs, f.boot.state_flash.programOpCount());
    EXPECT_EQ(floor_programs, f.boot.floor_flash.programOpCount());
    EXPECT_EQ(0, std::memcmp(original.ownerPublicKey, f.fx.integration.leanReceiver().status().ownerPublicKey, 32));
    for (uint32_t i = 0; i < f.command_flash.rawSize(); ++i) ASSERT_EQ(0xff, f.command_flash.rawBuffer()[i]);
    f.stage(6, true); ASSERT_FALSE(HasFatalFailure());
    const auto ready = f.fx.integration.leanReceiver().status();
    ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, ready.phase);
    ASSERT_EQ(6u, ready.counter);
    EXPECT_EQ(0, std::memcmp(original.imageHash, ready.imageHash, 32));
    EXPECT_NE(original.transactionNonce, ready.transactionNonce);
    f.boot.accessor.image = old_running;  // Later USB restoration of the exact previously-bound bank.
    f.fx.integration = OtaFirmwareIntegration(); f.reattach();
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, f.fx.integration.leanReceiver().status().phase);
    for (uint32_t i = 0; i < f.command_flash.rawSize(); ++i) ASSERT_EQ(0xff, f.command_flash.rawBuffer()[i]);
    if (const char* directory = std::getenv("OTA_NRF_REMOTE_BOOT_PROOF_DIR")) {
      OtaNrf52RunningContext context; ASSERT_TRUE(f.running.read(context));
      const auto save = [&](const char* name, const uint8_t* data, size_t bytes) {
        char path[512];
        const int length = std::snprintf(path, sizeof(path), "%s/%08x-role%u-retired-%s.bin",
                                         directory, board, unsigned(role), name);
        ASSERT_GT(length, 0); ASSERT_LT(static_cast<size_t>(length), sizeof(path));
        FILE* output = std::fopen(path, "wb"); ASSERT_NE(nullptr, output);
        const auto written = std::fwrite(data, 1, bytes, output);
        EXPECT_EQ(0, std::fclose(output)); ASSERT_EQ(bytes, written);
      };
      save("previous-command", command, sizeof(command));
      save("command-region", f.command_flash.rawBuffer(), f.command_flash.rawSize());
      save("state-region", f.boot.state_flash.rawBuffer(), f.boot.state_flash.rawSize());
      save("candidate", f.image.data(), f.image.size());
      save("canonical", f.canonical, sizeof(f.canonical));
      save("running", old_running.data(), old_running.size());
      save("sdk", context.settings, sizeof(context.settings));
      save("floor", f.boot.floor_flash.rawBuffer(), f.boot.floor_flash.rawSize());
      ASSERT_FALSE(HasFatalFailure());
    }
  }
}

TEST(LoraOtaLifecycle, InterruptedCancellationCannotReleaseReadyWhileAnyMatchingIntentSurvives) {
  using Cmd = ::ota::storage::XiaoOtaCommandRecordV3;
  using Flash = ::ota::test::FakeNorFlash;
  for (const auto timing : {Flash::InjectionTiming::Before, Flash::InjectionTiming::Mid, Flash::InjectionTiming::After}) {
    for (const uint32_t interrupted_erase : {1u, 2u}) {
      SCOPED_TRACE(::testing::Message() << "timing=" << unsigned(timing) << " erase=" << interrupted_erase);
      UnadmittedFixture f; f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
      uint8_t duplicate[Cmd::kRecordBytes];
      ASSERT_TRUE(Cmd::readNewest(f.command, duplicate));
      LifecycleFixture::le32(duplicate + 8, Cmd::sequenceOf(duplicate) - 1);
      LifecycleFixture::le32(duplicate + Cmd::kCrcOffset,
          ::ota::storage::Crc32::computeFinalized(duplicate, Cmd::kCrcOffset));
      const auto offset = Cmd::isValidRecord(f.command_flash.rawBuffer(), Cmd::kRecordBytes) ? 4096 : 0;
      ASSERT_TRUE(::ota::platform::isOk(f.command.program(offset, duplicate, sizeof(duplicate))));
      const auto old_running = f.boot.accessor.image;
      f.boot.accessor.image.back() ^= 1;
      const auto before = f.fx.integration.leanReceiver().status();
      f.command_flash.armFault({Flash::OpKind::Erase, timing, f.command_flash.eraseOpCount() + interrupted_erase, 32});
      EXPECT_EQ(usb::UsbOtaResult::IoError, f.abort());
      f.command_flash.clearFault();
      f.boot.accessor.image = old_running;
      f.fx.integration = OtaFirmwareIntegration(); f.reattach();
      f.manifest(6);
      const auto erases = f.fx.image_flash.eraseOpCount();
      const auto programs = f.fx.image_flash.programOpCount();
      const auto next = f.fx.integration.leanReceiver().begin(f.owner.publicKey(), f.canonical, f.signature, true, false);
      if (timing == Flash::InjectionTiming::After && interrupted_erase == 2) {
        // Both slots were physically erased, although the last driver acknowledgment was lost.
        EXPECT_EQ(usb::UsbOtaResult::Ok, next);
        for (uint32_t i = 0; i < f.command_flash.rawSize(); ++i) ASSERT_EQ(0xff, f.command_flash.rawBuffer()[i]);
      } else {
        EXPECT_EQ(usb::UsbOtaResult::TooLate, next);
        EXPECT_EQ(erases, f.fx.image_flash.eraseOpCount());
        EXPECT_EQ(programs, f.fx.image_flash.programOpCount());
        const auto owned = f.fx.integration.leanReceiver().status();
        EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, owned.phase);
        EXPECT_EQ(before.counter, owned.counter);
        EXPECT_EQ(0, std::memcmp(before.ownerPublicKey, owned.ownerPublicKey, 32));
        EXPECT_EQ(0, std::memcmp(before.imageHash, owned.imageHash, 32));
      }
    }
  }
}

TEST(LoraOtaLifecycle, UnadmittedRecoveryAcceptsPairedTerminalSidecarButNeverUnexplainedOrTornStateDebris) {
  for (int fault = 0; fault < 8; ++fault) {
    UnadmittedFixture f;
    f.boot.setState(::ota::storage::XiaoOtaStateReader::kPhaseConfirmed, 4, 17);
    f.boot.setFloor(4); f.reattach(); f.stage(); f.commit(); ASSERT_FALSE(HasFatalFailure());
    f.boot.accessor.image.back() ^= 1;
    const uint8_t* state = f.boot.state_flash.rawBuffer();
    uint8_t sidecar[88] = {};
    LifecycleFixture::le32(sidecar, 0x58534944);
    sidecar[4] = 1; sidecar[6] = sizeof(sidecar);
    std::memcpy(sidecar + 8, state + 8, 12);
    uint8_t accepted_command[::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes];
    ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(f.command, accepted_command));
    ::ota::trust::Sha256::hash(accepted_command, sizeof(accepted_command), sidecar + 20);
    std::memcpy(sidecar + 52, state + 36, 4);
    std::memcpy(sidecar + 60, state + 40, 4);
    if (fault == 1) sidecar[8] ^= 1;
    if (fault == 2) sidecar[12] ^= 1;
    if (fault == 3) sidecar[52] ^= 1;
    LifecycleFixture::le32(sidecar + 80, ::ota::storage::Crc32::computeFinalized(sidecar, 80));
    LifecycleFixture::le32(sidecar + 84, fault == 4 ? 0xffffffff : ::ota::storage::XiaoOtaStateReader::kCommitMarker);
    ASSERT_TRUE(::ota::platform::isOk(f.boot.state.program(0x100, sidecar, sizeof(sidecar))));
    if (fault == 5) {
      const uint8_t zero = 0;
      ASSERT_TRUE(::ota::platform::isOk(f.boot.state.program(4095, &zero, 1)));
    }
    if (fault == 6 || fault == 7) {
      uint8_t old[::ota::storage::XiaoOtaStateReader::kRecordBytes];
      std::memcpy(old, state, sizeof(old));
      LifecycleFixture::le32(old + 8, 0);
      LifecycleFixture::le32(old + 20, ::ota::storage::XiaoOtaStateReader::kPhaseTrialBoot);
      if (fault == 6) old[12] ^= 1;
      LifecycleFixture::le32(old + 144, ::ota::storage::Crc32::computeFinalized(old, 144));
      ASSERT_TRUE(::ota::platform::isOk(f.boot.state.program(4096, old, sizeof(old))));
    }
    const auto command_erases = f.command_flash.eraseOpCount();
    const auto journal_writes = f.fx.candidate_flash.programOpCount();
    EXPECT_EQ(fault == 0 || fault == 7 ? usb::UsbOtaResult::Ok : usb::UsbOtaResult::TooLate, f.abort());
    if (fault != 0 && fault != 7) {
      EXPECT_EQ(command_erases, f.command_flash.eraseOpCount());
      EXPECT_EQ(journal_writes, f.fx.candidate_flash.programOpCount());
    }
  }
}

TEST(LoraOtaLifecycle, UnadmittedRecoveryNeverGrantsCompetingOwnerFailedReceptionOrUnsignedAbortPrivilege) {
  UnadmittedFixture f; f.stage(5, false, true); ASSERT_FALSE(HasFatalFailure());
  uint8_t other_seed[32] = {0x9e};
  ::ota::test::Ed25519TestSigner other(other_seed);
  f.fx.admins.add(other.publicKey());
  f.manifest(6); other.sign(f.canonical, sizeof(f.canonical), f.signature);
  const auto erases = f.fx.image_flash.eraseOpCount();
  EXPECT_EQ(usb::UsbOtaResult::Busy, f.fx.integration.leanReceiver().begin(
      other.publicKey(), f.canonical, f.signature, true, false));
  EXPECT_EQ(erases, f.fx.image_flash.eraseOpCount());
  UnadmittedFixture committed; committed.stage(); committed.commit(); ASSERT_FALSE(HasFatalFailure());
  committed.boot.accessor.image.back() ^= 1;
  uint8_t invalid_signature[64] = {};
  const auto st = committed.fx.integration.leanReceiver().status();
  const auto writes = committed.fx.candidate_flash.programOpCount();
  EXPECT_EQ(usb::UsbOtaResult::Denied, committed.fx.integration.leanReceiver().abort(
      committed.owner.publicKey(), invalid_signature, st.imageHash, st.generation));
  EXPECT_EQ(writes, committed.fx.candidate_flash.programOpCount());
}

TEST(LoraOtaLifecycle, RealMeshRemoteSignedCommitDefersResetAfterDurableIntentAndExportsExactBootHandoff) {
  for (const uint32_t board : {0x584E3430u, 0x53435031u}) for (const uint8_t role : {0, 1}) {
    UnadmittedFixture f(board, role);
    ::ota::trust::Sha256::hash(f.boot.accessor.image.data(), f.boot.accessor.image.size(), f.boot.hash);
    f.boot.setFloor(4); f.reattach(); f.manifest(5);
    FakeClock clock; clock.now = 100;
    PacketCaptureRadio radio; radio.airtime = 20;
    StaticPoolPacketManager manager(8);
    PacketBoundaryRng rng; PacketBoundaryRtc rtc; PacketBoundaryTables tables;
    ProductionPacketMesh mesh(radio, clock, rng, rtc, manager, tables);
    mesh.begin();
    mesh.getOtaIntegration() = f.fx.integration;
    auto& integration = mesh.getOtaIntegration();
    int resets = 0;
    integration.attachCommitReboot(&resets, [](void* ctx) { ++*static_cast<int*>(ctx); });
    auto deliver = [&](const uint8_t* frame, size_t len) {
      Packet packet = {};
      packet.header = ROUTE_TYPE_DIRECT | (PAYLOAD_TYPE_LORA_OTA << PH_TYPE_SHIFT);
      packet.payload_len = len; std::memcpy(packet.payload, frame, len);
      EXPECT_EQ(ACTION_RELEASE, mesh.onRecvPacket(&packet));
    };
    uint8_t frame[kOtaOwnerSignedBlockMaxBytes];
    size_t len = encodeOtaTargetAuthorization(f.fx.target_public_key, f.owner.publicKey(),
                                              f.canonical, f.signature, frame, sizeof(frame));
    deliver(frame, len);
    ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Receiving, integration.leanReceiver().status().phase);
    uint8_t hash[32]; computeOtaManifestHash(f.canonical, hash);
    for (uint16_t block = 0; block < 2; ++block) {
      len = signAndEncodeOtaBlock(hash, block, f.image.data() + block * 84, 84, &f.owner,
                                 &ed25519TestSignerThunk, frame, sizeof(frame), f.owner.publicKey());
      deliver(frame, len);
    }
    mesh.loop();
    ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, integration.leanReceiver().status().phase);
    EXPECT_FALSE(integration.takeCommitReboot(99999, false, false));
    uint8_t message[usb::kCommitSignedBytes], signature[64];
    usb::buildCommitSignedMessage(f.fx.target_public_key, hash, 5, message);
    f.owner.sign(message, sizeof(message), signature);
    len = encodeOtaCommitFrame(f.fx.target_public_key, hash, 5, signature, frame, sizeof(frame));
    deliver(frame, len);
    ::ota::storage::OtaCandidateStore::Snapshot durable;
    ASSERT_TRUE(f.fx.candidate_store.load(durable));
    ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, durable.phase);
    EXPECT_TRUE(integration.hasPendingRfWork());
    EXPECT_FALSE(integration.takeCommitReboot(2099, false, false));
    EXPECT_FALSE(integration.takeCommitReboot(2100, false, false));  // Status reply still awaits dispatch.
    const auto command_writes = f.command_flash.programOpCount();
    const auto journal_writes = f.fx.candidate_flash.programOpCount();
    clock.now = 1000; deliver(frame, len);  // Original ACK lost; retry cannot rewrite or postpone reset.
    EXPECT_EQ(command_writes, f.command_flash.programOpCount());
    EXPECT_EQ(journal_writes, f.fx.candidate_flash.programOpCount());
    clock.now = 1001; mesh.loop();
    EXPECT_FALSE(integration.takeCommitReboot(2100, mesh.isSendInProgress(), manager.getOutboundTotal() != 0));
    clock.now = 1002; mesh.loop();
    ASSERT_GT(radio.sends, 0);
    EXPECT_FALSE(integration.takeCommitReboot(2100, mesh.isSendInProgress(), manager.getOutboundTotal() != 0));
    clock.now = 1003; mesh.loop();
    ASSERT_FALSE(mesh.isSendInProgress());
    ASSERT_EQ(0, manager.getOutboundTotal());
    EXPECT_FALSE(integration.takeCommitReboot(2100, true, false));
    EXPECT_FALSE(integration.takeCommitReboot(2100, false, true));
    EXPECT_FALSE(integration.takeCommitReboot(2100, false, false, true));
    EXPECT_TRUE(integration.tickCommitReboot(2100, false, false));
    EXPECT_EQ(1, resets);
    EXPECT_FALSE(integration.takeCommitReboot(2101, false, false));
    deliver(frame, len);
    EXPECT_FALSE(integration.takeCommitReboot(99999, false, false));
    uint8_t command[::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes];
    ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(f.command, command));
    EXPECT_EQ(integration.leanReceiver().status().transactionNonce,
              ::ota::storage::XiaoOtaCommandRecordV3::transactionNonceOf(command));
    if (const char* directory = std::getenv("OTA_NRF_REMOTE_BOOT_PROOF_DIR")) {
      OtaNrf52RunningContext sdk; ASSERT_TRUE(f.running.read(sdk));
      const auto save = [&](const char* name, const uint8_t* data, size_t size) {
        char path[512];
        const int length = std::snprintf(path, sizeof(path), "%s/%08x-role%u-%s.bin", directory, board,
                                         unsigned(role), name);
        ASSERT_GT(length, 0); ASSERT_LT(static_cast<size_t>(length), sizeof(path));
        FILE* output = std::fopen(path, "wb"); ASSERT_NE(nullptr, output);
        const auto written = std::fwrite(data, 1, size, output);
        EXPECT_EQ(0, std::fclose(output)); ASSERT_EQ(size, written);
      };
      save("command", command, sizeof(command));
      save("candidate", f.image.data(), f.image.size());
      save("running", f.boot.accessor.image.data(), f.boot.accessor.image.size());
      save("sdk", sdk.settings, sizeof(sdk.settings));
      save("floor", f.boot.floor_flash.rawBuffer(), f.boot.floor_flash.rawSize());
      ASSERT_FALSE(HasFatalFailure());
    }
    OtaFirmwareIntegration cold;
    cold.attachTrustProvider(f.trust.get()); cold.attachStagingSink(&f.sink);
    cold.attachCandidateStore(&f.fx.candidate_store); cold.attachLeanSignatureVerifier(&f.fx.sig_verifier);
    cold.setLeanAdminCheck(&f.fx.admins, &leanAdminCheckThunk); cold.setLeanTargetPublicKey(f.fx.target_public_key);
    cold.attachCommitReboot(&resets, [](void* ctx) { ++*static_cast<int*>(ctx); });
    EXPECT_TRUE(cold.handleReceivedFrame(frame, len, 3000));
    cold.releaseOutboundControlFrame();
    EXPECT_FALSE(cold.takeCommitReboot(99999, false, false));
  }
}

TEST(LoraOtaLifecycle, RemoteCommitErrorsAndUncertainJournalNeverArmResetUntilSignedDurableRetry) {
  for (int fault = 0; fault < 7; ++fault) {
    UnadmittedFixture f; f.stage(); ASSERT_FALSE(HasFatalFailure());
    auto& integration = f.fx.integration;
    int resets = 0;
    integration.attachCommitReboot(&resets, [](void* ctx) { ++*static_cast<int*>(ctx); });
    const auto st = integration.leanReceiver().status();
    uint8_t target[32], hash[32], message[usb::kCommitSignedBytes], signature[64], frame[kOtaCommitFrameBytes];
    std::memcpy(target, f.fx.target_public_key, 32); std::memcpy(hash, st.manifestHash, 32);
    uint32_t counter = 5;
    if (fault == 0) target[0] ^= 1;
    if (fault == 1) hash[0] ^= 1;
    if (fault == 2) counter = 6;
    usb::buildCommitSignedMessage(target, hash, counter, message);
    f.owner.sign(message, sizeof(message), signature);
    if (fault == 3) signature[0] ^= 1;
    if (fault == 4) f.fx.admins.count = 0;
    using Flash = ::ota::test::FakeNorFlash;
    if (fault == 5) f.command_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::After,
                                             f.command_flash.programOpCount() + 1});
    if (fault == 6) f.fx.candidate_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Before,
                                                 f.fx.candidate_flash.programOpCount() + 1});
    auto len = encodeOtaCommitFrame(target, hash, counter, signature, frame, sizeof(frame));
    EXPECT_FALSE(integration.handleReceivedFrame(frame, len, 100));
    EXPECT_FALSE(integration.takeCommitReboot(99999, false, false));
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, integration.leanReceiver().status().phase);
    if (fault == 6) {
      f.fx.candidate_flash.clearFault();
      EXPECT_TRUE(integration.handleReceivedFrame(frame, len, 200));
      integration.releaseOutboundControlFrame();
      EXPECT_FALSE(integration.takeCommitReboot(2199, false, false));
      EXPECT_TRUE(integration.takeCommitReboot(2200, false, false));
    }
  }
}

TEST(LoraOtaLifecycle, DeferredCommitResetWaitsForRestorationButQueueLossDoesNotBlockAndClockWrapIsSafe) {
  UnadmittedFixture f; f.stage(); ASSERT_FALSE(HasFatalFailure());
  const uint8_t seed[32] = {0x91};
  RfNode radio_node(seed);
  auto& integration = f.fx.integration;
  int resets = 0;
  integration.attachCommitReboot(&resets, [](void* ctx) { ++*static_cast<int*>(ctx); });
  integration.setLeanTargetPublicKey(radio_node.signer.publicKey());
  integration.attachRfIdentity(&radio_node, &RfNode::sign, &RfNode::radio, 907525);
  const auto st = integration.leanReceiver().status();
  uint8_t direct[kOtaDirectFrameBytes], message[160], signature[64];
  ASSERT_EQ(sizeof(direct), encodeOtaDirectFrame(kOtaDirectRequestKind, f.owner.publicKey(),
      radio_node.signer.publicKey(), st.manifestHash, 908525, 60000, 1, direct, sizeof(direct)));
  auto len = buildOtaDirectMessage(direct, message);
  f.owner.sign(message, len, direct + 107);
  ASSERT_TRUE(integration.handleReceivedFrame(direct, sizeof(direct), 100));
  integration.releaseOutboundControlFrame();
  integration.tickDirect(200, true); integration.tickDirect(5200, true);
  ASSERT_TRUE(integration.directActive());
  radio_node.failRestore = true;
  usb::buildCommitSignedMessage(radio_node.signer.publicKey(), st.manifestHash, 5, message);
  f.owner.sign(message, usb::kCommitSignedBytes, signature);
  uint8_t commit[kOtaCommitFrameBytes];
  len = encodeOtaCommitFrame(radio_node.signer.publicKey(), st.manifestHash, 5, signature, commit, sizeof(commit));
  const uint32_t now = 0xfffffff0;
  ASSERT_TRUE(integration.handleReceivedFrame(commit, len, now));
  EXPECT_FALSE(integration.takeCommitReboot(now + 15000, false, true, true));
  radio_node.failRestore = false;
  EXPECT_FALSE(integration.takeCommitReboot(now + 1999, false, false));
  EXPECT_TRUE(integration.takeCommitReboot(now + 15000, false, true, true));
  EXPECT_EQ(907525u, radio_node.frequency);
  EXPECT_FALSE(integration.directActive());
}

TEST(LoraOtaLifecycle, ProvenNeverAdmittedAbortCancelsDeferredResetAndImmediateNewCampaignGetsItsOwnDeadline) {
  UnadmittedFixture f; f.stage(); ASSERT_FALSE(HasFatalFailure());
  auto& integration = f.fx.integration;
  int resets = 0;
  integration.attachCommitReboot(&resets, [](void* ctx) { ++*static_cast<int*>(ctx); });
  const auto commit = [&](uint32_t now) {
    const auto st = integration.leanReceiver().status();
    uint8_t message[usb::kCommitSignedBytes], signature[64], frame[kOtaCommitFrameBytes];
    usb::buildCommitSignedMessage(f.fx.target_public_key, st.manifestHash, st.counter, message);
    f.owner.sign(message, sizeof(message), signature);
    auto len = encodeOtaCommitFrame(f.fx.target_public_key, st.manifestHash, st.counter, signature, frame, sizeof(frame));
    ASSERT_TRUE(integration.handleReceivedFrame(frame, len, now));
  };
  commit(100); ASSERT_FALSE(HasFatalFailure());
  f.boot.accessor.image.back() ^= 1;
  ASSERT_EQ(usb::UsbOtaResult::Ok, f.abort());
  f.image[0] ^= 1; f.stage(6, true); ASSERT_FALSE(HasFatalFailure());
  commit(500); ASSERT_FALSE(HasFatalFailure());
  integration.releaseOutboundControlFrame();
  EXPECT_FALSE(integration.tickCommitReboot(2100, false, false));
  EXPECT_TRUE(integration.tickCommitReboot(2500, false, false));
  EXPECT_EQ(1, resets);

  UnadmittedFixture aborted; aborted.stage(); ASSERT_FALSE(HasFatalFailure());
  aborted.fx.integration.attachCommitReboot(&resets, [](void* ctx) { ++*static_cast<int*>(ctx); });
  const auto st = aborted.fx.integration.leanReceiver().status();
  uint8_t message[usb::kCommitSignedBytes], signature[64];
  usb::buildCommitSignedMessage(aborted.fx.target_public_key, st.manifestHash, st.counter, message);
  aborted.owner.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, aborted.fx.integration.commitAndDeferReboot(st.counter, signature, 100));
  aborted.boot.accessor.image.back() ^= 1;
  ASSERT_EQ(usb::UsbOtaResult::Ok, aborted.abort());
  EXPECT_FALSE(aborted.fx.integration.tickCommitReboot(99999, false, false));
  EXPECT_EQ(1, resets);
}

TEST(LoraOtaLifecycle, ContinuousOrdinaryTrafficCannotPostponeAuthorizedResetPastQueueGrace) {
  UnadmittedFixture f; f.stage(); ASSERT_FALSE(HasFatalFailure());
  auto& integration = f.fx.integration;
  int resets = 0;
  integration.attachCommitReboot(&resets, [](void* ctx) { ++*static_cast<int*>(ctx); });
  const auto st = integration.leanReceiver().status();
  uint8_t message[usb::kCommitSignedBytes], signature[64];
  usb::buildCommitSignedMessage(f.fx.target_public_key, st.manifestHash, st.counter, message);
  f.owner.sign(message, sizeof(message), signature);
  ASSERT_EQ(usb::UsbOtaResult::Ok, integration.commitAndDeferReboot(st.counter, signature, 100));
  EXPECT_FALSE(integration.tickCommitReboot(15099, true, true, true));
  EXPECT_TRUE(integration.tickCommitReboot(15100, true, true, true));
  EXPECT_EQ(1, resets);
}

TEST(LoraOtaLifecycle, ThreeProductionNrfCampaignsRetireOnlyConfirmedOrCompletedRollbackWithFreshFloorAndNonce) {
  for (const uint32_t board : {0x584E3430u, 0x53435031u}) {
    for (const uint8_t role : {0, 1}) {
      for (const bool first_failed : {false, true}) {
        SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << first_failed);
        LeanFixture fx;
        LifecycleFixture boot;
        ::ota::test::FakeNorFlash command_flash{8192, 4096};
        ::ota::platform::FlashRegion command{command_flash, 0, 8192};
        LifecycleCommandProvider provider(boot.accessor.image);
        uint8_t seed[32] = {0x58};
        ::ota::test::Ed25519TestSigner owner(seed);
        fx.admins.add(owner.publicKey());
        auto anchor = makeLeanTrustAnchor();
        anchor.expected_target_id = board;
        anchor.expected_role_id = role;
        uint64_t previous_nonce = 0;
        uint8_t previous_canonical[59] = {}, previous_signature[64] = {};
        for (uint32_t campaign = 0; campaign < 3; ++campaign) {
          ::ota::trust::Sha256 hasher;
          OtaBoardFailClosedMonotonicCounter counter(boot.floor);
          ::ota::trust::DescriptorVerifier verifier(hasher, fx.sig_verifier, counter, anchor);
          OtaNrf52FirmwareTrustProvider trust(verifier, fx.image_region);
          OtaFirmwareStorageSink sink(fx.image_region, &command, &provider);
          OtaBoardBootLifecycleObserver observer(boot.state, boot.floor, boot.accessor);
          for (int tick = 0; tick < 10; ++tick) observer.tick(true);
          fx.integration.attachTrustProvider(&trust);
          fx.integration.attachStagingSink(&sink);
          fx.integration.attachCandidateStore(&fx.candidate_store);
          fx.integration.attachBootLifecycle(&observer, [](void* ctx, OtaBootLifecycleEvidence& out) {
            return static_cast<OtaBoardBootLifecycleObserver*>(ctx)->read(true, out);
          });
          auto& receiver = fx.integration.leanReceiver();
          if (campaign) {
            EXPECT_EQ(first_failed && campaign == 1 ? usb::UsbOtaPhase::Failed : usb::UsbOtaPhase::Installed,
                      fx.integration.reportedPhase());
            const auto image_erases = fx.image_flash.eraseOpCount();
            const auto metadata_programs = fx.candidate_flash.programOpCount();
            if (!(first_failed && campaign == 1)) {
              EXPECT_EQ(usb::UsbOtaResult::Denied,
                        receiver.begin(owner.publicKey(), previous_canonical, previous_signature, true, false));
              EXPECT_EQ(image_erases, fx.image_flash.eraseOpCount());
              EXPECT_EQ(metadata_programs, fx.candidate_flash.programOpCount());
            }
          }
          const uint32_t security_counter = 5 + campaign - (first_failed && campaign ? 1 : 0);
          std::vector<uint8_t> image(84 * (campaign + 1), static_cast<uint8_t>(0x51 + campaign));
          if (first_failed && campaign == 1) image.assign(84, 0x51);
          auto descriptor = buildProtocolDescriptor(image.data(), image.size(), security_counter);
          descriptor.boardFamily = static_cast<uint16_t>(board >> 16);
          descriptor.boardVariant = static_cast<uint16_t>(board);
          descriptor.role = role;
          uint8_t canonical[59], signature[64];
          size_t len = 0;
          ASSERT_EQ(OtaDescriptorCodecResult::Ok,
                    encodeOtaDescriptorCanonical(descriptor, canonical, sizeof(canonical), len));
          owner.sign(canonical, sizeof(canonical), signature);
          ASSERT_EQ(usb::UsbOtaResult::Ok,
                    receiver.begin(owner.publicKey(), canonical, signature,
                                   first_failed && campaign == 1, false));
          for (uint16_t block = 0; block < receiver.status().totalBlocks; ++block) {
            ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.putBlock(block, image.data() + block * 84u, 84));
          }
          ASSERT_EQ(usb::UsbOtaResult::Pending, receiver.requestSeal());
          receiver.loop();
          ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, receiver.status().phase);
          const auto ready = receiver.status();
          uint8_t message[usb::kCommitSignedBytes];
          usb::buildCommitSignedMessage(fx.target_public_key, ready.manifestHash, security_counter, message);
          owner.sign(message, sizeof(message), signature);
          ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.commit(security_counter, signature));
          uint8_t durable[::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes];
          ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(command, durable));
          EXPECT_EQ(ready.transactionNonce, ::ota::storage::XiaoOtaCommandRecordV3::transactionNonceOf(durable));
          EXPECT_NE(previous_nonce, ready.transactionNonce);
          previous_nonce = ready.transactionNonce;
          std::memcpy(previous_canonical, canonical, sizeof(canonical));
          owner.sign(canonical, sizeof(canonical), previous_signature);
          const auto backup = boot.accessor.image;
          uint8_t backup_hash[32];
          ::ota::trust::Sha256::hash(backup.data(), backup.size(), backup_hash);
          ASSERT_TRUE(::ota::platform::isOk(boot.state.eraseSector(0)));
          ASSERT_TRUE(::ota::platform::isOk(boot.state.eraseSector(4096)));
          const bool failed = first_failed && campaign == 0;
          if (!failed) boot.accessor.image = image;
          boot.setState(failed ? ::ota::storage::XiaoOtaStateReader::kPhaseFailedMax :
                                 ::ota::storage::XiaoOtaStateReader::kPhaseConfirmed,
                        security_counter, ready.transactionNonce, ready.imageHash, backup_hash, backup.size());
          if (!failed) {
            ASSERT_TRUE(::ota::platform::isOk(boot.floor.eraseSector(0)));
            ASSERT_TRUE(::ota::platform::isOk(boot.floor.eraseSector(4096)));
            boot.setFloor(security_counter);
          }
          const auto programs = fx.candidate_flash.programOpCount();
          const auto erases = fx.candidate_flash.eraseOpCount();
          OtaBoardBootLifecycleObserver completed(boot.state, boot.floor, boot.accessor);
          for (int tick = 0; tick < 10; ++tick) completed.tick(true);
          fx.integration.attachBootLifecycle(&completed, [](void* ctx, OtaBootLifecycleEvidence& out) {
            return static_cast<OtaBoardBootLifecycleObserver*>(ctx)->read(true, out);
          });
          EXPECT_EQ(failed ? usb::UsbOtaPhase::Failed : usb::UsbOtaPhase::Installed,
                    fx.integration.reportedPhase());
          EXPECT_EQ(programs, fx.candidate_flash.programOpCount());
          EXPECT_EQ(erases, fx.candidate_flash.eraseOpCount());
          EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, receiver.status().phase);
        }
      }
    }
  }
}

TEST(LoraOtaLifecycle, FailedBootPhaseDoesNotReleaseUntilFreshRunningBackupOrNewerFloorActuallyMatches) {
  const uint8_t zero_hash[32] = {};
  for (int fault = 0; fault < 5; ++fault) {
    LifecycleFixture f;
    uint8_t candidate_hash[32] = {0x93};
    ::ota::trust::Sha256::hash(f.accessor.image.data(), f.accessor.image.size(), f.hash);
    f.setState(::ota::storage::XiaoOtaStateReader::kPhaseFailedMax, 5, 17,
               candidate_hash, fault == 4 ? zero_hash : f.hash,
               f.accessor.image.size() + (fault == 2 ? 1 : 0));
    if (fault == 0) f.accessor.image[0] ^= 1;
    if (fault == 1) f.accessor.fail = true;
    if (fault == 4) f.accessor.fail_with_output = true;
    OtaBootLifecycleEvidence evidence;
    ASSERT_TRUE(f.observer.read(true, evidence));
    EXPECT_EQ(0, std::memcmp(evidence.imageHash, zero_hash, 32));
    if (fault != 3) {
      for (int tick = 0; tick < 10; ++tick) f.observer.tick(true);
      ASSERT_TRUE(f.observer.read(true, evidence));
      EXPECT_EQ(0, std::memcmp(evidence.imageHash, zero_hash, 32));
    }
  }
  LifecycleFixture f;
  uint8_t candidate_hash[32] = {0x93}, wrong_backup[32] = {0xA3};
  f.setState(::ota::storage::XiaoOtaStateReader::kPhaseFailedMax, 5, 17, candidate_hash, wrong_backup, 4096);
  f.setFloor(6);
  for (int tick = 0; tick < 10; ++tick) f.observer.tick(true);
  OtaBootLifecycleEvidence evidence;
  ASSERT_TRUE(f.observer.read(true, evidence));
  EXPECT_EQ(0, std::memcmp(candidate_hash, evidence.imageHash, 32));
  EXPECT_FALSE(evidence.imageVerified);
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
struct BootReadbackFixture {
  RfProductHarness h;
  OtaBootLifecycleEvidence boot;
  ::ota::storage::OtaCandidateStore::Snapshot candidate;
  OtaFirmwareIntegration cold;
  bool readable = true;
  unsigned reads = 0;
  unsigned lifecycleReads = 0;

  void prepare() {
    h.prepare(91, usb::kStartModeDirected);
    for (int i = 0; i < 20 && !h.ready(h.a); ++i) h.step();
    ASSERT_TRUE(h.ready(h.a));
    auto& receiver = h.a.fx.integration.leanReceiver();
    const auto st = receiver.status();
    uint8_t message[usb::kCommitSignedBytes], signature[64];
    usb::buildCommitSignedMessage(h.a.signer.publicKey(), st.manifestHash, st.counter, message);
    h.sender.signer.sign(message, sizeof(message), signature);
    ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.commit(st.counter, signature));
    ASSERT_TRUE(h.a.fx.candidate_store.load(candidate));
    setBoot(usb::UsbOtaPhase::Installed);
    attach(cold);
  }
  void setBoot(usb::UsbOtaPhase phase) {
    const auto st = OtaLeanReceiver::snapshotStatus(candidate);
    boot = OtaBootLifecycleEvidence();
    boot.phase = phase;
    boot.imageVerified = phase != usb::UsbOtaPhase::Failed;
    boot.counter = st.counter;
    boot.transactionNonce = st.transactionNonce;
    std::memcpy(boot.imageHash, st.imageHash, sizeof(boot.imageHash));
    boot.floorKnown = true;
    boot.confirmedFloor = phase == usb::UsbOtaPhase::Installed ? st.counter : st.counter - 1;
  }
  void attach(OtaFirmwareIntegration& integration) {
    integration.setLeanTargetPublicKey(h.a.signer.publicKey());
    integration.attachBootLifecycle(this, &lifecycle, &provenance);
  }
  static bool lifecycle(void* ctx, OtaBootLifecycleEvidence& out) {
    auto& fixture = *static_cast<BootReadbackFixture*>(ctx);
    ++fixture.lifecycleReads;
    out = fixture.boot;
    return true;
  }
  static bool provenance(void* ctx, const OtaBootLifecycleEvidence&,
                         ::ota::storage::OtaCandidateStore::Snapshot& out) {
    auto& fixture = *static_cast<BootReadbackFixture*>(ctx);
    ++fixture.reads;
    if (!fixture.readable ||
        !fixture.h.a.fx.sig_verifier.verify(fixture.candidate.signature, 64, fixture.candidate.canonical,
                                            sizeof(fixture.candidate.canonical),
                                            fixture.candidate.ownerPublicKey, 32)) return false;
    out = fixture.candidate;
    return true;
  }
};
}

TEST(LoraOtaLifecycle, CommittedCandidateCannotRetireForTrialUnknownOrMismatchedTerminalProof) {
  for (int fault = 0; fault < 12; ++fault) {
    SCOPED_TRACE(fault);
    BootReadbackFixture f;
    f.prepare();
    ASSERT_FALSE(HasFatalFailure());
    auto& integration = f.h.a.fx.integration;
    f.attach(integration);
    switch (fault) {
      case 0: f.setBoot(usb::UsbOtaPhase::Trial); break;
      case 1: f.setBoot(usb::UsbOtaPhase::Unknown); break;
      case 2: ++f.boot.counter; break;
      case 3: ++f.boot.transactionNonce; break;
      case 4: f.boot.imageHash[0] ^= 1; break;
      case 5: f.boot.imageVerified = false; break;
      case 6: f.boot.floorKnown = false; break;
      case 7: ++f.boot.confirmedFloor; break;
      case 8:
      case 9: {
        auto record = f.candidate;
        if (fault == 8) record.signature[0] ^= 1; else ++record.totalBlocks;
        ASSERT_TRUE(f.h.a.fx.candidate_store.append(record));
        integration.attachCandidateStore(&f.h.a.fx.candidate_store);
        break;
      }
      case 10:
        f.setBoot(usb::UsbOtaPhase::Failed);
        std::memset(f.boot.imageHash, 0, sizeof(f.boot.imageHash));
        break;
      case 11:
        integration.attachBootLifecycle(&f, [](void*, OtaBootLifecycleEvidence&) { return false; });
        break;
    }
    const auto before = integration.leanReceiver().status();
    const auto programs = f.h.a.fx.candidate_flash.programOpCount() + f.h.a.fx.image_flash.programOpCount();
    const auto erases = f.h.a.fx.candidate_flash.eraseOpCount() + f.h.a.fx.image_flash.eraseOpCount();
    uint8_t image[40] = {0x73}, canonical[59], signature[64];
    f.h.a.fx.buildSmallManifest(image, sizeof(image), canonical, 6);
    f.h.sender.signer.sign(canonical, sizeof(canonical), signature);
    EXPECT_EQ(usb::UsbOtaResult::Busy,
              integration.leanReceiver().begin(f.h.sender.signer.publicKey(), canonical, signature, true, false));
    EXPECT_EQ(before.transactionNonce, integration.leanReceiver().status().transactionNonce);
    EXPECT_EQ(before.phase, integration.leanReceiver().status().phase);
    EXPECT_EQ(programs, f.h.a.fx.candidate_flash.programOpCount() + f.h.a.fx.image_flash.programOpCount());
    EXPECT_EQ(erases, f.h.a.fx.candidate_flash.eraseOpCount() + f.h.a.fx.image_flash.eraseOpCount());
  }
}

TEST(LoraOtaLifecycle, ActualTerminalBootResolvesReadyJournalCommitUncertaintyWithoutReleasingActiveTrial) {
  BootReadbackFixture f;
  f.prepare();
  ASSERT_FALSE(HasFatalFailure());
  auto ready = f.candidate;
  ready.phase = ::ota::storage::OtaCandidateStore::Phase::Ready;
  ASSERT_TRUE(f.h.a.fx.candidate_store.append(ready));
  auto& integration = f.h.a.fx.integration;
  integration.attachCandidateStore(&f.h.a.fx.candidate_store);
  f.attach(integration);
  uint8_t image[40] = {0x73}, canonical[59], signature[64];
  f.h.a.fx.buildSmallManifest(image, sizeof(image), canonical, 6);
  f.h.sender.signer.sign(canonical, sizeof(canonical), signature);
  f.setBoot(usb::UsbOtaPhase::Trial);
  const auto erases = f.h.a.fx.image_flash.eraseOpCount();
  EXPECT_EQ(usb::UsbOtaResult::Busy,
            integration.leanReceiver().begin(f.h.sender.signer.publicKey(), canonical, signature, true, false));
  EXPECT_EQ(erases, f.h.a.fx.image_flash.eraseOpCount());
  f.setBoot(usb::UsbOtaPhase::Installed);
  ASSERT_EQ(usb::UsbOtaResult::Ok,
            integration.leanReceiver().begin(f.h.sender.signer.publicKey(), canonical, signature, false, false));
  EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Receiving, integration.leanReceiver().status().phase);
  EXPECT_NE(f.boot.transactionNonce, integration.leanReceiver().status().transactionNonce);
}

TEST(LoraOtaLifecycle, VerifiedNewerRunningProjectionDoesNotGrantRetirementForDifferentCommittedOrFailedAttempt) {
  for (const bool committed : {true, false}) {
    BootReadbackFixture f;
    f.prepare();
    ASSERT_FALSE(HasFatalFailure());
    LeanFixture inactive;
    auto old = f.candidate;
    old.phase = committed ? ::ota::storage::OtaCandidateStore::Phase::Committed :
                            ::ota::storage::OtaCandidateStore::Phase::Failed;
    usb::putBE32(old.canonical + 45, f.boot.counter - 1);
    f.h.sender.signer.sign(old.canonical, sizeof(old.canonical), old.signature);
    ASSERT_TRUE(inactive.candidate_store.reset(old));
    for (uint16_t index = 0; index < old.totalBlocks; ++index) ASSERT_TRUE(inactive.candidate_store.markReceived(index));
    inactive.integration.attachCandidateStore(&inactive.candidate_store);
    inactive.admins.add(f.h.sender.signer.publicKey());
    f.attach(inactive.integration);
    const auto before = inactive.integration.leanReceiver().status();
    EXPECT_EQ(usb::UsbOtaPhase::Installed, inactive.integration.reportedPhase());
    EXPECT_EQ(before.transactionNonce, inactive.integration.leanReceiver().status().transactionNonce);
    uint8_t image[40] = {0x73}, canonical[59], signature[64];
    inactive.buildSmallManifest(image, sizeof(image), canonical, 6);
    f.h.sender.signer.sign(canonical, sizeof(canonical), signature);
    const auto erases = inactive.image_flash.eraseOpCount();
    const auto programs = inactive.candidate_flash.programOpCount();
    EXPECT_EQ(usb::UsbOtaResult::Busy,
              inactive.integration.leanReceiver().begin(f.h.sender.signer.publicKey(), canonical, signature, false, false));
    EXPECT_EQ(erases, inactive.image_flash.eraseOpCount());
    EXPECT_EQ(programs, inactive.candidate_flash.programOpCount());
    EXPECT_EQ(before.transactionNonce, inactive.integration.leanReceiver().status().transactionNonce);
  }
}

TEST(LoraOtaLifecycle, ColdBootTrialAndInstalledReadbacksNeedNoWritableBackendAndKeepUsbAbi2AndRfBinding) {
  BootReadbackFixture f;
  f.prepare();
  ASSERT_FALSE(HasFatalFailure());
  const auto programs = f.h.a.fx.candidate_flash.programOpCount() + f.h.a.fx.image_flash.programOpCount();
  const auto erases = f.h.a.fx.candidate_flash.eraseOpCount() + f.h.a.fx.image_flash.eraseOpCount();
  for (const auto phase : {usb::UsbOtaPhase::Trial, usb::UsbOtaPhase::Installed}) {
    f.setBoot(phase);
    EXPECT_FALSE(f.cold.backendAvailable());
    EXPECT_FALSE(f.cold.leanReceiver().hasStore());
    EXPECT_FALSE(f.cold.leanReceiver().status().valid);
    const auto view = f.cold.readback();
    ASSERT_TRUE(view.snapshot.valid);
    EXPECT_TRUE(view.bootCandidate);
    EXPECT_EQ(phase, view.phase);
    EXPECT_EQ(f.boot.counter, view.snapshot.counter);
    usb::UsbOtaReply reply;
    reply.setNoSnapshot();
    f.cold.fillUsbReadback(reply);
    EXPECT_NE(0, reply.flags & usb::kReplyFlagSnapshotValid);
    EXPECT_EQ(phase, reply.phase);
    EXPECT_EQ(f.boot.counter, reply.counter);
    EXPECT_EQ(view.snapshot.totalBlocks, reply.durableReceivedBlocks);
    uint8_t encoded[usb::kReplyBytes];
    EXPECT_EQ(90u, usb::encodeUsbOtaReply(reply, encoded));
    EXPECT_EQ(view.snapshot.generation, usb::getBE32(encoded + 86));
    char text[160];
    formatOtaBootLifecycleStatus(text, sizeof(text), f.boot, view.phase, view.snapshot.counter);
    EXPECT_NE(nullptr, std::strstr(text, phase == usb::UsbOtaPhase::Trial ?
                                  "boot=trial phase=trial" : "boot=confirmed phase=installed"));
    EXPECT_NE(nullptr, std::strstr(text, "counter=5"));
    uint8_t poll[kOtaCensusPollBytes], report[kOtaCensusReportBytes];
    encodeOtaCensusPoll(f.h.a.signer.publicKey(), view.snapshot.manifestHash, 0, poll, sizeof(poll));
    ASSERT_TRUE(f.cold.handleReceivedFrame(poll, sizeof(poll), 1000));
    size_t len = 0;
    ASSERT_TRUE(f.cold.peekOutboundControlFrame(report, sizeof(report), len, 1250));
    f.cold.releaseOutboundControlFrame();
    ASSERT_TRUE(f.h.sender.fx.integration.handleReceivedFrame(report, len, 1250));
    OtaFirmwareIntegration::TargetObservation observed;
    ASSERT_TRUE(f.h.sender.fx.integration.targetObservation(f.h.a.signer.publicKey(), 1250, observed));
    EXPECT_EQ(phase, observed.lifecyclePhase);
    EXPECT_EQ(f.boot.counter, observed.counter);
    EXPECT_EQ(view.snapshot.generation, observed.generation);
    EXPECT_EQ(3u, observed.bitmap[0]);
    poll[33] ^= 1;
    ASSERT_TRUE(f.cold.handleReceivedFrame(poll, sizeof(poll), 1500));
    EXPECT_FALSE(f.cold.peekOutboundControlFrame(report, sizeof(report), len, 1750));
    EXPECT_EQ(usb::UsbOtaResult::Unavailable,
              f.cold.leanReceiver().begin(f.candidate.ownerPublicKey, f.candidate.canonical,
                                          f.candidate.signature, false, false));
    EXPECT_EQ(usb::UsbOtaResult::NotFound, f.cold.leanReceiver().commit(f.boot.counter, f.candidate.signature));
  }
  EXPECT_EQ(programs, f.h.a.fx.candidate_flash.programOpCount() + f.h.a.fx.image_flash.programOpCount());
  EXPECT_EQ(erases, f.h.a.fx.candidate_flash.eraseOpCount() + f.h.a.fx.image_flash.eraseOpCount());
}

TEST(LoraOtaLifecycle, VerifiedRunningProvenanceOverridesSupersededInactiveMetadataWithoutReplacingReceiverStore) {
  BootReadbackFixture f;
  f.prepare();
  ASSERT_FALSE(HasFatalFailure());
  auto old = f.candidate;
  usb::putBE32(old.canonical + 45, f.boot.counter - 1);
  f.h.sender.signer.sign(old.canonical, sizeof(old.canonical), old.signature);
  using Phase = ::ota::storage::OtaCandidateStore::Phase;
  for (const auto phase : {Phase::Receiving, Phase::Verifying, Phase::Ready, Phase::Committed,
                           Phase::Failed, Phase::Aborted}) {
    LeanFixture inactive;
    old.phase = phase;
    ASSERT_TRUE(inactive.candidate_store.reset(old));
    for (uint16_t i = 0; i < old.totalBlocks; ++i) ASSERT_TRUE(inactive.candidate_store.markReceived(i));
    inactive.integration.leanReceiver().attachCandidateStore(&inactive.candidate_store);
    f.attach(inactive.integration);
    const auto before = inactive.integration.leanReceiver().status();
    const auto programs = inactive.candidate_flash.programOpCount() + inactive.image_flash.programOpCount();
    const auto erases = inactive.candidate_flash.eraseOpCount() + inactive.image_flash.eraseOpCount();
    const auto view = inactive.integration.readback();
    ASSERT_TRUE(view.bootCandidate);
    EXPECT_EQ(usb::UsbOtaPhase::Installed, view.phase);
    EXPECT_EQ(f.boot.counter, view.snapshot.counter);
    EXPECT_NE(0, std::memcmp(before.manifestHash, view.snapshot.manifestHash, 32));
    EXPECT_EQ(before.counter, inactive.integration.leanReceiver().status().counter);
    EXPECT_EQ(before.transactionNonce, inactive.integration.leanReceiver().status().transactionNonce);
    EXPECT_EQ(programs, inactive.candidate_flash.programOpCount() + inactive.image_flash.programOpCount());
    EXPECT_EQ(erases, inactive.candidate_flash.eraseOpCount() + inactive.image_flash.eraseOpCount());
  }
}

TEST(LoraOtaLifecycle, NewCandidateAndLocalCacheKeepTheirOwnStatusWhileOldBootCanBePolledByExactHash) {
  BootReadbackFixture f;
  f.prepare();
  ASSERT_FALSE(HasFatalFailure());
  usb::putBE32(f.candidate.canonical + 45, f.boot.counter - 1);
  f.h.sender.signer.sign(f.candidate.canonical, sizeof(f.candidate.canonical), f.candidate.signature);
  f.setBoot(usb::UsbOtaPhase::Installed);
  ::ota::storage::OtaCandidateStore::Snapshot current;
  ASSERT_TRUE(f.h.a.fx.candidate_store.load(current));
  using Phase = ::ota::storage::OtaCandidateStore::Phase;
  for (const auto phase : {Phase::Receiving, Phase::Verifying, Phase::Ready, Phase::Committed}) {
    LeanFixture active;
    current.phase = phase;
    ASSERT_TRUE(active.candidate_store.reset(current));
    for (uint16_t i = 0; i < current.totalBlocks; ++i) ASSERT_TRUE(active.candidate_store.markReceived(i));
    active.integration.leanReceiver().attachCandidateStore(&active.candidate_store);
    f.attach(active.integration);
    EXPECT_EQ(OtaFirmwareIntegration::candidatePhase(phase), active.integration.readback().phase);
    EXPECT_EQ(OtaLeanReceiver::snapshotStatus(current).counter, active.integration.readback().snapshot.counter);
    const auto installed = OtaLeanReceiver::snapshotStatus(f.candidate);
    const auto queried = active.integration.readback(f.boot, installed.manifestHash);
    ASSERT_TRUE(queried.bootCandidate);
    EXPECT_EQ(usb::UsbOtaPhase::Installed, queried.phase);
    EXPECT_EQ(installed.counter, queried.snapshot.counter);
  }
  ::ota::storage::OtaCandidateStore::Snapshot cache;
  ASSERT_TRUE(f.h.sender.fx.candidate_store.load(cache));
  cache.localCache = true;
  ASSERT_TRUE(f.h.sender.fx.candidate_store.append(cache));
  f.h.sender.fx.integration.leanReceiver().attachCandidateStore(&f.h.sender.fx.candidate_store);
  f.attach(f.h.sender.fx.integration);
  f.reads = 0;
  f.lifecycleReads = 0;
  const auto cached = f.h.sender.fx.integration.readback();
  EXPECT_EQ(usb::UsbOtaPhase::CacheSealed, cached.phase);
  EXPECT_FALSE(cached.bootCandidate);
  EXPECT_EQ(0u, f.reads);
  EXPECT_EQ(0u, f.lifecycleReads);
}

TEST(LoraOtaLifecycle, ColdBootReadbackRejectsInvalidSignatureGeometryBindingAndOptimisticInstalledEvidence) {
  for (int fault = 0; fault < 14; ++fault) {
    BootReadbackFixture f;
    f.prepare();
    ASSERT_FALSE(HasFatalFailure());
    switch (fault) {
      case 0: f.candidate.signature[0] ^= 1; break;
      case 1: f.candidate.localCache = true; break;
      case 2: f.candidate.phase = ::ota::storage::OtaCandidateStore::Phase::Ready; break;
      case 3: ++f.candidate.exactSizeBytes; break;
      case 4: ++f.candidate.totalBlocks; break;
      case 5: --f.candidate.receivedBlocks; break;
      case 6: ++f.boot.transactionNonce; break;
      case 7: ++f.boot.counter; break;
      case 8: f.boot.imageHash[0] ^= 1; break;
      case 9: f.boot.floorKnown = false; break;
      case 10: ++f.boot.confirmedFloor; break;
      case 11: f.boot.imageVerified = false; break;
      case 12: f.readable = false; break;
      case 13: f.candidate.ownerPublicKey[0] ^= 1; break;
    }
    EXPECT_FALSE(f.cold.readback().snapshot.valid);
    EXPECT_EQ(usb::UsbOtaPhase::Unknown, f.cold.reportedPhase());
    usb::UsbOtaReply reply;
    reply.setNoSnapshot();
    f.cold.fillUsbReadback(reply);
    EXPECT_EQ(0, reply.flags & usb::kReplyFlagSnapshotValid);
    EXPECT_EQ(usb::UsbOtaPhase::Unknown, reply.phase);
  }
}

TEST(LoraOtaLifecycle, AuthorizedSameCounterRepairKeepsActiveReadyInsteadOfOlderFailedBootAttempt) {
  BootReadbackFixture f;
  f.prepare();
  ASSERT_FALSE(HasFatalFailure());
  auto retry = f.candidate;
  retry.phase = ::ota::storage::OtaCandidateStore::Phase::Ready;
  ++retry.sessionId;
  f.candidate.phase = ::ota::storage::OtaCandidateStore::Phase::Failed;
  f.setBoot(usb::UsbOtaPhase::Failed);
  LeanFixture active;
  ASSERT_TRUE(active.candidate_store.reset(retry));
  for (uint16_t i = 0; i < retry.totalBlocks; ++i) ASSERT_TRUE(active.candidate_store.markReceived(i));
  active.integration.leanReceiver().attachCandidateStore(&active.candidate_store);
  f.attach(active.integration);
  const auto view = active.integration.readback();
  EXPECT_FALSE(view.bootCandidate);
  EXPECT_EQ(usb::UsbOtaPhase::Ready, view.phase);
  EXPECT_EQ(f.boot.counter, view.snapshot.counter);
  EXPECT_NE(f.boot.transactionNonce, view.snapshot.transactionNonce);
}

TEST(LoraOtaLifecycle, MissingConfirmedFloorAndSignedFailedProvenanceNeverClaimInstalled) {
  BootReadbackFixture f;
  f.prepare();
  ASSERT_FALSE(HasFatalFailure());
  f.boot.phase = usb::UsbOtaPhase::Unknown;
  f.boot.floorKnown = false;
  EXPECT_EQ(usb::UsbOtaPhase::CommitPending, f.cold.reportedPhase());
  EXPECT_EQ(f.boot.counter, f.cold.readback().snapshot.counter);
  f.candidate.phase = ::ota::storage::OtaCandidateStore::Phase::Failed;
  f.setBoot(usb::UsbOtaPhase::Failed);
  const auto failed = f.cold.readback();
  ASSERT_TRUE(failed.bootCandidate);
  EXPECT_EQ(usb::UsbOtaPhase::Failed, failed.phase);
  EXPECT_FALSE(f.boot.imageVerified);
  char text[160];
  formatOtaBootLifecycleStatus(text, sizeof(text), f.boot, failed.phase, failed.snapshot.counter);
  EXPECT_NE(nullptr, std::strstr(text, "boot=failed phase=failed"));
  EXPECT_NE(nullptr, std::strstr(text, "verified=0 image=unknown"));
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

#include "StockBootPreflightTests.h"

namespace {
struct QualifiedOriginalRunningContext : StockRunningContext {
  uint8_t unusedSdkByte = 0;
  uint32_t hookAt = 0;
  void* hookContext = nullptr;
  void (*hook)(void*) = nullptr;
  explicit QualifiedOriginalRunningContext(std::vector<uint8_t>& bytes) : StockRunningContext(bytes) {}
  bool read(OtaNrf52RunningContext& out) const override {
    if (!StockRunningContext::read(out)) return false;
    if (!vendorCrcDisabled && sizeOverride != UINT32_MAX && sizeOverride <= out.capacity) {
      const auto crc = ::ota::storage::XiaoOtaActiveExtentBridge::crc16Compute(out.image, sizeOverride) ^
          (badCrc ? 1 : 0);
      out.settings[2] = crc; out.settings[3] = crc >> 8;
    }
    out.settings[24] = unusedSdkByte;
    if (hook && reads == hookAt) hook(hookContext);
    return true;
  }
};
struct QualifiedOriginalFixture {
  UnadmittedFixture f;
  QualifiedOriginalRunningContext running{f.boot.accessor.image};
  OtaBoardOriginalSnapshotProvider original{f.boot.state, f.boot.floor, running, f.qualified};
  OtaBoardInstallCommandProviderV3 provider{original};
  OtaFirmwareStorageSink sink{f.fx.image_region, &f.command, &provider};
  OtaBoardUnadmittedCommandRecovery recovery{f.command, f.boot.state, f.boot.floor, f.fx.image_region,
      f.fx.sig_verifier, running, f.qualified, f.target, f.role};
  std::unique_ptr<OtaBoardBootLifecycleObserver> observer;
  explicit QualifiedOriginalFixture(uint32_t board = 0x584e3430, uint8_t role = 0) : f(board, role) {
    f.boot.accessor.image.resize(9004, 0xff);
    running.vendorCrcDisabled = true;
    running.sizeOverride = 9001;
    ::ota::trust::Sha256::hash(f.boot.accessor.image.data(), f.boot.accessor.image.size(), f.boot.hash);
    setGenesisFloor();
    attach();
  }
  void setGenesisFloor() {
    using Floor = ::ota::storage::XiaoOtaFloorReader;
    uint8_t record[Floor::kRecordBytes] = {};
    LifecycleFixture::le32(record, Floor::kMagic);
    record[4] = Floor::kRecordVersion; record[6] = sizeof(record);
    LifecycleFixture::le32(record + 8, 1);
    LifecycleFixture::le32(record + Floor::kCrcOffset, ::ota::storage::Crc32::computeFinalized(record, Floor::kCrcOffset));
    LifecycleFixture::le32(record + Floor::kCommitMarkerOffset, Floor::kCommitMarker);
    ASSERT_TRUE(::ota::platform::isOk(f.boot.floor.program(0, record, sizeof(record))));
  }
  void attach() {
    f.reattach();
    f.fx.integration.attachStagingSink(&sink);
    f.fx.integration.attachUnadmittedAbort(&recovery, &OtaBoardUnadmittedCommandRecovery::invoke);
    observer.reset(new OtaBoardBootLifecycleObserver(f.boot.state, f.boot.floor, original));
    f.fx.integration.attachBootLifecycle(observer.get(), [](void* ctx, OtaBootLifecycleEvidence& out) {
      return static_cast<OtaBoardBootLifecycleObserver*>(ctx)->read(true, out);
    });
  }
  void restoredState() {
    using State = ::ota::storage::XiaoOtaStateReader;
    const auto status = f.fx.integration.leanReceiver().status();
    OtaNrf52RunningContext sdk;
    ASSERT_TRUE(running.read(sdk));
    f.boot.setState(State::kPhaseFailedMax, status.counter, status.transactionNonce, status.imageHash,
                   f.boot.hash, f.boot.accessor.image.size());
    uint8_t state[State::kRecordBytes];
    ASSERT_TRUE(::ota::platform::isOk(f.boot.state.read(0, state, sizeof(state))));
    std::memcpy(state + 36, sdk.settings, 4); std::memcpy(state + 40, sdk.settings + 8, 4);
    LifecycleFixture::le32(state + State::kCrcOffset, ::ota::storage::Crc32::computeFinalized(state, State::kCrcOffset));
    ASSERT_TRUE(::ota::platform::isOk(f.boot.state.eraseSector(0)));
    ASSERT_TRUE(::ota::platform::isOk(f.boot.state.program(0, state, sizeof(state))));
    uint8_t sidecar[88] = {};
    LifecycleFixture::le32(sidecar, 0x58534944);
    sidecar[4] = 1; sidecar[6] = sizeof(sidecar);
    std::memcpy(sidecar + 8, state + 8, 12);
    uint8_t command[::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes];
    ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(f.command, command));
    ::ota::trust::Sha256::hash(command, sizeof(command), sidecar + 20);
    std::memcpy(sidecar + 52, sdk.settings, sizeof(sdk.settings));
    LifecycleFixture::le32(sidecar + 80, ::ota::storage::Crc32::computeFinalized(sidecar, 80));
    LifecycleFixture::le32(sidecar + 84, State::kCommitMarker);
    ASSERT_TRUE(::ota::platform::isOk(f.boot.state.program(0x100, sidecar, sizeof(sidecar))));
  }
};
}

TEST(LoraOtaQualifiedOriginal, VendorZeroFactoryFloorProducesRealSignedCommitWordRoundedV3AndLiteralHandoff) {
  using Command = ::ota::storage::XiaoOtaCommandRecordV3;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1}) {
    SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role));
    QualifiedOriginalFixture q(board, role);
    ASSERT_FALSE(HasFatalFailure());
    OtaBoardOriginalImageSnapshot snapshot;
    OtaBoardOriginalSnapshotProvider::Context context;
    ASSERT_TRUE(q.original.read(snapshot, context));
    EXPECT_EQ(OtaBoardOriginalSnapshotProvider::Context::FactoryFloor, context);
    ASSERT_NE(0, snapshot.computedCrc);
    EXPECT_EQ(9004u, snapshot.image.active_image_extent);
    EXPECT_EQ(0, snapshot.running.settings[2]); EXPECT_EQ(0, snapshot.running.settings[3]);
    EXPECT_EQ(0u, ::ota::storage::XiaoOtaActiveExtentBridge::resolve(
        ::ota::storage::XiaoOtaActiveExtentBridge::decodeBank0FromRaw28Bytes(snapshot.running.settings),
        snapshot.running.image, snapshot.running.capacity).active_image_extent);
    q.f.stage(1); ASSERT_FALSE(HasFatalFailure());
    const auto ready = q.f.fx.integration.leanReceiver().status();
    uint8_t message[usb::kCommitSignedBytes], signature[64], frame[kOtaCommitFrameBytes];
    usb::buildCommitSignedMessage(q.f.fx.target_public_key, ready.manifestHash, ready.counter, message);
    q.f.owner.sign(message, sizeof(message), signature);
    const auto length = encodeOtaCommitFrame(q.f.fx.target_public_key, ready.manifestHash, ready.counter,
                                            signature, frame, sizeof(frame));
    int resets = 0;
    q.f.fx.integration.attachCommitReboot(&resets, [](void* ctx) { ++*static_cast<int*>(ctx); });
    ASSERT_TRUE(q.f.fx.integration.handleReceivedFrame(frame, length, 100));
    ASSERT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, q.f.fx.integration.leanReceiver().status().phase);
    q.f.fx.integration.releaseOutboundControlFrame();
    ASSERT_TRUE(q.f.fx.integration.tickCommitReboot(2100, false, false));
    EXPECT_EQ(1, resets);
    uint8_t command[Command::kRecordBytes];
    ASSERT_TRUE(Command::readNewest(q.f.command, command));
    ASSERT_EQ(220u, sizeof(command));
    EXPECT_EQ(9004u, Command::activeImageExtentOf(command));
    EXPECT_EQ(0, std::memcmp(Command::activeImageHashOf(command), q.f.boot.hash, 32));
    EXPECT_EQ(0, std::memcmp(Command::wireDescriptorOf(command), q.f.canonical, 59));
    EXPECT_EQ(0, std::memcmp(Command::admittedSignerKeyOf(command), q.f.owner.publicKey(), 32));
    OtaNrf52RunningContext sdk;
    ASSERT_TRUE(q.running.read(sdk));
    EXPECT_EQ(0, std::memcmp(sdk.settings, snapshot.running.settings, sizeof(sdk.settings)));
    EXPECT_EQ(0u, q.f.boot.state_flash.programOpCount());
    EXPECT_EQ(1u, q.f.boot.floor_flash.programOpCount());
    if (const char* directory = std::getenv("OTA_NRF_REMOTE_BOOT_PROOF_DIR")) {
      const auto save = [&](const char* suffix, const uint8_t* bytes, size_t size) {
        char path[512];
        const int length = std::snprintf(path, sizeof(path), "%s/%08x-role%u-original-%s.bin",
                                         directory, board, unsigned(role), suffix);
        ASSERT_GT(length, 0); ASSERT_LT(static_cast<size_t>(length), sizeof(path));
        FILE* output = std::fopen(path, "wb"); ASSERT_NE(nullptr, output);
        EXPECT_EQ(size, std::fwrite(bytes, 1, size, output)); EXPECT_EQ(0, std::fclose(output));
      };
      save("command", command, sizeof(command));
      save("candidate", q.f.image.data(), q.f.image.size());
      save("running", q.f.boot.accessor.image.data(), q.f.boot.accessor.image.size());
      save("sdk", sdk.settings, sizeof(sdk.settings));
      save("floor", q.f.boot.floor_flash.rawBuffer(), q.f.boot.floor_flash.rawSize());
      save("state-region", q.f.boot.state_flash.rawBuffer(), q.f.boot.state_flash.rawSize());
      ASSERT_FALSE(HasFatalFailure());
    }
  }
}

TEST(LoraOtaQualifiedOriginal, ProductionColdGateRequiresPresentGenesisAndReadyCommitNeverDefaultsBlankOrTornFloor) {
  using Flash = ::ota::test::FakeNorFlash;
  using Store = ::ota::storage::OtaCandidateStore;
  using Floor = OtaBoardOriginalSnapshotProvider::FloorInitialization;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1})
    for (int fault = 0; fault < 4; ++fault) {
      SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << fault);
      QualifiedOriginalFixture q(board, role);
      q.f.stage(1); ASSERT_FALSE(HasFatalFailure());
      if (fault == 0 || fault == 2) {
        uint8_t genesis[::ota::storage::XiaoOtaFloorReader::kRecordBytes];
        ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.read(0, genesis, sizeof(genesis))));
        ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.eraseSector(0)));
        if (fault == 2) {
          q.f.boot.floor_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Mid,
                                        q.f.boot.floor_flash.programOpCount() + 1, 17});
          ASSERT_FALSE(::ota::platform::isOk(q.f.boot.floor.program(0, genesis, sizeof(genesis))));
          q.f.boot.floor_flash.clearFault();
        }
      }
      q.f.fx.integration = OtaFirmwareIntegration();
      q.attach();
      if (fault == 3)
        q.f.boot.floor_flash.armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before,
                                      q.f.boot.floor_flash.readOpCount() + 1});
      OtaBoardFailClosedMonotonicCounter counter(q.f.boot.floor);
      const auto gate = resolveOtaBoardOriginalInstallGate(true, q.original, counter);
      EXPECT_EQ(fault == 1, gate.install_capable);
      if (fault == 0) {
        EXPECT_STREQ("STAGING_ONLY: floor not initialized", gate.reason);
        EXPECT_EQ(Floor::Blank, q.original.floorInitialization());
      }
      if (fault == 2) EXPECT_EQ(Floor::Unproven, q.original.floorInitialization());
      if (fault == 1) {
        EXPECT_EQ(Floor::Initialized, q.original.floorInitialization());
        EXPECT_EQ(0u, gate.floor_value);
      }
      OtaFirmwareStorageSink cold_sink(q.f.fx.image_region, &q.f.command, gate.install_capable ? &q.provider : nullptr);
      q.f.fx.integration.attachStagingSink(&cold_sink);
      ASSERT_EQ(Store::Phase::Ready, q.f.fx.integration.leanReceiver().status().phase);
      const auto ready = q.f.fx.integration.leanReceiver().status();
      uint8_t message[usb::kCommitSignedBytes], signature[64], frame[kOtaCommitFrameBytes];
      usb::buildCommitSignedMessage(q.f.fx.target_public_key, ready.manifestHash, ready.counter, message);
      q.f.owner.sign(message, sizeof(message), signature);
      const auto length = encodeOtaCommitFrame(q.f.fx.target_public_key, ready.manifestHash, ready.counter,
                                              signature, frame, sizeof(frame));
      int resets = 0;
      q.f.fx.integration.attachCommitReboot(&resets, [](void* ctx) { ++*static_cast<int*>(ctx); });
      EXPECT_EQ(fault == 1, q.f.fx.integration.handleReceivedFrame(frame, length, 100));
      q.f.fx.integration.releaseOutboundControlFrame();
      EXPECT_EQ(fault == 1, q.f.fx.integration.tickCommitReboot(2100, false, false));
      EXPECT_EQ(fault == 1 ? 1 : 0, resets);
      EXPECT_EQ(fault == 1 ? Store::Phase::Committed : Store::Phase::Ready,
                q.f.fx.integration.leanReceiver().status().phase);
      q.observer->tick(true);
      OtaBootLifecycleEvidence evidence;
      ASSERT_TRUE(q.observer->read(true, evidence));
      EXPECT_NE(usb::UsbOtaPhase::Installed, evidence.phase);
      if (fault == 0 || fault == 2) EXPECT_FALSE(evidence.floorKnown);
      if (fault == 1) {
        EXPECT_TRUE(evidence.floorKnown); EXPECT_EQ(0u, evidence.confirmedFloor);
        uint8_t command[::ota::storage::XiaoOtaCommandRecordV3::kRecordBytes];
        ASSERT_TRUE(::ota::storage::XiaoOtaCommandRecordV3::readNewest(q.f.command, command));
        EXPECT_EQ(9004u, ::ota::storage::XiaoOtaCommandRecordV3::activeImageExtentOf(command));
        EXPECT_EQ(0, std::memcmp(q.f.boot.hash,
                               ::ota::storage::XiaoOtaCommandRecordV3::activeImageHashOf(command), 32));
      } else {
        EXPECT_EQ(0u, q.f.command_flash.programOpCount());
        if (fault == 0 || fault == 2) {
          Flash confirm_flash(8192, 4096);
          ::ota::platform::FlashRegion confirm(confirm_flash, 0, 8192);
          const bool safe = q.original.ordinaryWritesAllowed(q.f.command, confirm, q.f.fx.sig_verifier, board, role);
          EXPECT_FALSE(safe);
          const auto decision = resolveOtaBoardOriginalStartupDecision(
              true, ::ota::storage::XiaoOtaStateReader::ReadStatus::Blank, 0, safe);
          EXPECT_NE(OtaBoardStartupDecisionStatus::Normal, decision.status);
          Adafruit_LittleFS filesystem;
          PacketBoundaryRtc clock;
          DataStore store(filesystem, clock);
          store.begin(decision.status == OtaBoardStartupDecisionStatus::Normal, false);
          NodePrefs prefs;
          EXPECT_FALSE(store.savePrefs(prefs));
          EXPECT_EQ(0u, filesystem.mounts);
          EXPECT_EQ(0u, filesystem.writes);
        }
      }
    }
}

TEST(LoraOtaQualifiedOriginal, ActualFloorCapabilityReadbackFitsBothRolesAndKeepsBlockedObservationReadOnly) {
  using Flash = ::ota::test::FakeNorFlash;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1})
    for (int fault = 0; fault < 5; ++fault) for (bool blocked : {false, true}) {
      SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << fault << '/' << blocked);
      QualifiedOriginalFixture q(board, role);
      ASSERT_FALSE(HasFatalFailure());
      if (fault == 1 || fault == 2) {
        uint8_t record[::ota::storage::XiaoOtaFloorReader::kRecordBytes];
        ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.read(0, record, sizeof(record))));
        ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.eraseSector(0)));
        if (fault == 2) {
          q.f.boot.floor_flash.armFault({Flash::OpKind::Program, Flash::InjectionTiming::Mid,
                                        q.f.boot.floor_flash.programOpCount() + 1, 17});
          ASSERT_FALSE(::ota::platform::isOk(q.f.boot.floor.program(0, record, sizeof(record))));
          q.f.boot.floor_flash.clearFault();
        }
      }
      if (fault == 3) {
        const uint8_t tail = 0;
        ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.program(8191, &tail, 1)));
      }
      if (fault == 4)
        q.f.boot.floor_flash.armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before,
                                      q.f.boot.floor_flash.readOpCount() + 18});
      const auto before = std::vector<uint8_t>(q.f.boot.floor_flash.rawBuffer(),
                                               q.f.boot.floor_flash.rawBuffer() + q.f.boot.floor_flash.rawSize());
      const auto programs = q.f.boot.floor_flash.programOpCount(), erases = q.f.boot.floor_flash.eraseOpCount();
      Adafruit_LittleFS filesystem;
      PacketBoundaryRtc clock;
      DataStore store(filesystem, clock);
      store.begin(!blocked, false);
      const auto filesystem_writes = filesystem.writes, filesystem_mounts = filesystem.mounts;
      char detail[kOtaBoardFloorCapabilityStatusBytes], repeater[160];
      formatOtaBoardFloorCapabilityStatus(detail, sizeof(detail), "INSTALL_CAPABLE: verified original", q.f.boot.floor);
      formatOtaOrdinaryWriteDiagnostic(repeater, sizeof(repeater), store.destructiveWritesDisallowed(), detail);
      uint8_t companion[176];
      const auto bytes = encodeOtaOrdinaryWriteDiagnostic(companion, sizeof(companion), 29,
                                                         store.destructiveWritesDisallowed(), detail);
      ASSERT_GT(bytes, 1u);
      EXPECT_EQ(29, companion[0]);
      EXPECT_STREQ(repeater, reinterpret_cast<char*>(companion + 1));
      EXPECT_NE(nullptr, std::strstr(repeater, blocked ? "writes=blocked " : "writes=allowed "));
      if (!fault) {
        const std::string expected = "INSTALL_CAPABLE: floor=present seq=00000001 ctr=00000000 ext=00000000 sha=" +
            std::string(64, '0') + " io=ok";
        EXPECT_EQ(expected, detail);
        EXPECT_EQ(159u, std::strlen(repeater));
        EXPECT_EQ(160u, bytes);
      } else {
        EXPECT_NE(nullptr, std::strstr(detail, fault == 1 ? "floor=blank" :
                                     fault == 4 ? "floor=read-error" : "floor=corrupt"));
        EXPECT_NE(nullptr, std::strstr(detail, "seq=? ctr=? ext=? sha=?"));
      }
      EXPECT_EQ(programs, q.f.boot.floor_flash.programOpCount());
      EXPECT_EQ(erases, q.f.boot.floor_flash.eraseOpCount());
      EXPECT_EQ(0, std::memcmp(before.data(), q.f.boot.floor_flash.rawBuffer(), before.size()));
      EXPECT_EQ(filesystem_writes, filesystem.writes);
      EXPECT_EQ(filesystem_mounts, filesystem.mounts);
    }
}

TEST(LoraOtaQualifiedOriginal, FullColdFailedMaxBothSdkPoliciesRestoreAfterCommandReplacementAndBindNextCommit) {
  using State = ::ota::storage::XiaoOtaStateReader;
  using Store = ::ota::storage::OtaCandidateStore;
  using Command = ::ota::storage::XiaoOtaCommandRecordV3;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1})
    for (bool vendor_crc_unused : {true, false}) {
    SCOPED_TRACE(::testing::Message() << board << '/' << unsigned(role) << '/' << vendor_crc_unused);
    QualifiedOriginalFixture q(board, role);
    q.running.vendorCrcDisabled = vendor_crc_unused;
    q.f.stage(1); q.f.commit(); ASSERT_FALSE(HasFatalFailure());
    if (const char* directory = std::getenv("OTA_NRF_ORIGINAL_FAILED_PROOF_DIR")) {
      const auto read = [&](const char* suffix, uint8_t* bytes, size_t size) {
        char path[512];
        const int length = std::snprintf(path, sizeof(path), "%s/%08x-role%u-original-failed%s-%s.bin",
                                         directory, board, unsigned(role), vendor_crc_unused ? "" : "-nonzero", suffix);
        ASSERT_GT(length, 0); ASSERT_LT(static_cast<size_t>(length), sizeof(path));
        FILE* input = std::fopen(path, "rb"); ASSERT_NE(nullptr, input);
        EXPECT_EQ(size, std::fread(bytes, 1, size, input)); EXPECT_EQ(EOF, std::fgetc(input));
        EXPECT_EQ(0, std::fclose(input));
      };
      for (auto* region : {&q.f.boot.state, &q.f.command}) {
        std::vector<uint8_t> bytes(region->sizeBytes());
        read(region == &q.f.boot.state ? "state-region" : "command-region", bytes.data(), bytes.size());
        ASSERT_FALSE(HasFatalFailure());
        for (uint32_t offset = 0; offset < region->sizeBytes(); offset += region->eraseUnitBytes())
          ASSERT_TRUE(::ota::platform::isOk(region->eraseSector(offset)));
        ASSERT_TRUE(::ota::platform::isOk(region->program(0, bytes.data(), bytes.size())));
      }
      read("running", q.f.boot.accessor.image.data(), q.f.boot.accessor.image.size());
      uint8_t sdk[28]; read("sdk", sdk, sizeof(sdk)); ASSERT_FALSE(HasFatalFailure());
      OtaNrf52RunningContext running;
      ASSERT_TRUE(q.running.read(running));
      ASSERT_EQ(0, std::memcmp(sdk, running.settings, sizeof(sdk)));
    } else {
      q.restoredState(); ASSERT_FALSE(HasFatalFailure());
    }
    q.f.fx.integration = OtaFirmwareIntegration();
    q.f.fx.admins.count = 0;
    q.attach(); q.observer->tick(true);
    OtaBoardFailClosedMonotonicCounter counter(q.f.boot.floor);
    const auto gate = resolveOtaBoardOriginalInstallGate(true, q.original, counter);
    ASSERT_TRUE(gate.install_capable); EXPECT_EQ(0u, gate.floor_value);
    OtaBootLifecycleEvidence evidence;
    ASSERT_TRUE(q.observer->read(true, evidence));
    EXPECT_EQ(usb::UsbOtaPhase::Failed, evidence.phase);
    EXPECT_TRUE(evidence.floorKnown); EXPECT_EQ(0u, evidence.confirmedFloor);
    const auto previous = q.f.fx.integration.leanReceiver().status();
    EXPECT_EQ(0, std::memcmp(previous.imageHash, evidence.imageHash, 32));
    uint8_t state[State::kRecordBytes], saved[28];
    ASSERT_EQ(State::ReadStatus::Found, State::readNewestWithStatus(q.f.boot.state, state));
    ASSERT_TRUE(q.original.readSavedOriginalSettings(state, saved));
    const auto saved_crc = uint16_t(saved[2]) | uint16_t(saved[3]) << 8;
    if (vendor_crc_unused) EXPECT_EQ(0, saved_crc);
    else EXPECT_EQ(::ota::storage::XiaoOtaActiveExtentBridge::crc16Compute(q.f.boot.accessor.image.data(), 9001),
                   saved_crc);
    uint8_t accepted[Command::kRecordBytes], accepted_digest[32], historical_digest[32];
    ASSERT_TRUE(Command::readNewest(q.f.command, accepted));
    ::ota::trust::Sha256::hash(accepted, sizeof(accepted), accepted_digest);
    const uint32_t state_slot = !std::memcmp(state, q.f.boot.state_flash.rawBuffer(), sizeof(state)) ? 0 : 4096;
    ASSERT_TRUE(::ota::platform::isOk(q.f.boot.state.read(state_slot + 0x100 + 20, historical_digest, 32)));
    EXPECT_EQ(0, std::memcmp(accepted_digest, historical_digest, 32));
    ::ota::storage::XiaoOtaCommandV3Fields replacement;
    replacement.transaction_nonce = Command::transactionNonceOf(accepted);
    std::memcpy(replacement.wire_descriptor, Command::wireDescriptorOf(accepted), sizeof(replacement.wire_descriptor));
    std::memcpy(replacement.signature_ed25519, Command::signatureOf(accepted), sizeof(replacement.signature_ed25519));
    std::memcpy(replacement.admitted_signer_public_key_ed25519, Command::admittedSignerKeyOf(accepted),
                sizeof(replacement.admitted_signer_public_key_ed25519));
    replacement.active_image_extent = Command::activeImageExtentOf(accepted);
    std::memcpy(replacement.active_image_hash_sha256, Command::activeImageHashOf(accepted), 32);
    // Two legitimate A/B appends retire both copies of the historical accepted command.
    ASSERT_TRUE(Command::writeNext(q.f.command, replacement));
    ASSERT_TRUE(Command::writeNext(q.f.command, replacement));
    for (uint32_t slot = 0; slot < 2; ++slot) {
      uint8_t record[Command::kRecordBytes], digest[32];
      ASSERT_TRUE(::ota::platform::isOk(q.f.command.read(slot * 4096, record, sizeof(record))));
      ASSERT_TRUE(Command::isValidRecord(record, sizeof(record)));
      ::ota::trust::Sha256::hash(record, sizeof(record), digest);
      EXPECT_NE(0, std::memcmp(historical_digest, digest, 32));
    }
    ::ota::test::FakeNorFlash confirm_flash(8192, 4096);
    ::ota::platform::FlashRegion confirm(confirm_flash, 0, 8192);
    const bool ordinary_proven = q.original.ordinaryWritesAllowed(q.f.command, confirm, q.f.fx.sig_verifier, board, role);
    ASSERT_TRUE(ordinary_proven);
    const auto decision = resolveOtaBoardOriginalStartupDecision(true, State::ReadStatus::Found,
                                                                 State::kPhaseFailedMax, ordinary_proven);
    ASSERT_EQ(OtaBoardStartupDecisionStatus::Normal, decision.status);
    Adafruit_LittleFS filesystem;
    ASSERT_EQ(0u, filesystem.mounts);
    ASSERT_TRUE(filesystem.begin());
    PacketBoundaryRtc clock;
    DataStore store(filesystem, clock);
    store.begin(decision.status == OtaBoardStartupDecisionStatus::Normal, false);
    NodePrefs prefs;
    std::strcpy(prefs.node_name, "OTA-LAB-RESTORED");
    ASSERT_TRUE(store.savePrefs(prefs));
    stock_acl_test::ClientACL acl;
    ASSERT_NE(nullptr, acl.putClient(mesh::Identity(q.f.owner.publicKey()), PERM_ACL_ADMIN));
    acl.save(&filesystem);
    EXPECT_EQ(PERM_ACL_ADMIN, filesystem.files.at("/s_contacts")->at(32));
    ASSERT_TRUE(resolveOtaBoardOriginalInstallGate(true, q.original, counter).install_capable);
    for (int fault = 0; fault < 3; ++fault) {
      if (fault == 0) q.running.unusedSdkByte = 1;
      if (fault == 1) q.f.boot.accessor.image[100] ^= 1;
      if (fault == 2) { q.running.vendorCrcDisabled = false; q.running.badCrc = true; }
      OtaBoardOriginalImageSnapshot snapshot;
      OtaBoardOriginalSnapshotProvider::Context context;
      EXPECT_FALSE(q.original.read(snapshot, context));
      EXPECT_FALSE(q.original.ordinaryWritesAllowed(q.f.command, confirm, q.f.fx.sig_verifier, board, role));
      if (fault == 0) q.running.unusedSdkByte = 0;
      if (fault == 1) q.f.boot.accessor.image[100] ^= 1;
      if (fault == 2) { q.running.vendorCrcDisabled = vendor_crc_unused; q.running.badCrc = false; }
    }
    OtaBoardOriginalImageSnapshot restored;
    OtaBoardOriginalSnapshotProvider::Context restored_context;
    ASSERT_TRUE(q.original.read(restored, restored_context));
    ASSERT_EQ(OtaBoardOriginalSnapshotProvider::Context::RestoredOriginal, restored_context);
    q.f.image[12] ^= 1; q.f.stage(2); ASSERT_FALSE(HasFatalFailure());
    const auto ready = q.f.fx.integration.leanReceiver().status();
    uint8_t seed[32] = {0x97}, message[usb::kAbortSignedBytes], signature[64];
    ::ota::test::Ed25519TestSigner admin(seed);
    q.f.fx.admins.add(admin.publicKey());
    usb::buildAbortSignedMessage(q.f.fx.target_public_key, ready.imageHash, ready.generation, message);
    admin.sign(message, sizeof(message), signature);
    const auto erases = q.f.command_flash.eraseOpCount();
    ASSERT_EQ(usb::UsbOtaResult::Ok,
              q.f.fx.integration.leanReceiver().abort(admin.publicKey(), signature, ready.imageHash, ready.generation));
    EXPECT_EQ(erases, q.f.command_flash.eraseOpCount());
    q.f.fx.integration = OtaFirmwareIntegration();
    q.f.fx.admins.count = 0;
    q.attach();
    q.f.fx.admins.add(admin.publicKey());
    EXPECT_EQ(Store::Phase::Aborted, q.f.fx.integration.leanReceiver().status().phase);
    EXPECT_EQ(usb::UsbOtaResult::Denied, q.f.fx.integration.leanReceiver().begin(
        q.f.owner.publicKey(), q.f.canonical, q.f.signature, false, false));
    q.f.image[24] ^= 1; q.f.stage(3, true); ASSERT_FALSE(HasFatalFailure());
    EXPECT_EQ(Store::Phase::Ready, q.f.fx.integration.leanReceiver().status().phase);
    q.f.commit(); ASSERT_FALSE(HasFatalFailure());
    uint8_t next_command[Command::kRecordBytes];
    ASSERT_TRUE(Command::readNewest(q.f.command, next_command));
    EXPECT_EQ(9004u, Command::activeImageExtentOf(next_command));
    EXPECT_EQ(0, std::memcmp(restored.image.active_image_hash_sha256, Command::activeImageHashOf(next_command), 32));
    EXPECT_EQ(0, std::memcmp(q.f.canonical, Command::wireDescriptorOf(next_command), sizeof(q.f.canonical)));
    EXPECT_EQ(0, std::memcmp(q.f.signature, Command::signatureOf(next_command), sizeof(q.f.signature)));
    EXPECT_EQ(0, std::memcmp(q.f.owner.publicKey(), Command::admittedSignerKeyOf(next_command), 32));
    EXPECT_EQ(Store::Phase::Committed, q.f.fx.integration.leanReceiver().status().phase);
  }
}

TEST(LoraOtaQualifiedOriginal, OriginalSnapshotNeverSkipsMissingFloorHistoryTrialCopySdkAndIoProofs) {
  using State = ::ota::storage::XiaoOtaStateReader;
  using Flash = ::ota::test::FakeNorFlash;
  for (int fault = 0; fault < 16; ++fault) {
    SCOPED_TRACE(fault);
    QualifiedOriginalFixture q;
    if (fault == 0) ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.eraseSector(0)));
    if (fault == 1) { const uint8_t byte = 0; ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.program(0, &byte, 1))); }
    if (fault >= 2 && fault <= 4) {
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.eraseSector(0)));
      q.f.boot.setFloor(fault == 2 ? 4 : 0, fault == 3, fault == 4);
    }
    if (fault == 5) q.f.boot.setState(State::kPhaseTrialBoot);
    if (fault == 6) q.f.boot.setState(4);
    if (fault == 7) q.f.boot.setState(State::kPhaseConfirmed, 0);
    if (fault == 8) q.running.invalid = true;
    if (fault == 9) q.running.bank1 = 1;
    if (fault == 10) q.running.tailErased = false;
    if (fault == 11) { q.running.vendorCrcDisabled = false; q.running.badCrc = true; }
    if (fault == 12) q.running.sizeOverride = q.f.boot.accessor.image.size() + 1;
    if (fault == 13) q.running.failAt = q.running.reads + 2;
    if (fault == 14 || fault == 15) {
      auto& flash = fault == 14 ? q.f.boot.state_flash : q.f.boot.floor_flash;
      flash.armFault({Flash::OpKind::Read, Flash::InjectionTiming::Before, flash.readOpCount() + 1});
    }
    ::ota::storage::XiaoOtaActiveExtentInfo image;
    EXPECT_FALSE(q.original.readOriginalSnapshot(image));
    EXPECT_EQ(0u, image.active_image_extent);
    EXPECT_EQ(0u, q.f.command_flash.programOpCount());
    EXPECT_EQ(0u, q.f.command_flash.eraseOpCount());
  }
}

TEST(LoraOtaQualifiedOriginal, RealGenesisPresenceAndStableWindowsAreRequiredNotNumericBlankZero) {
  using Floor = ::ota::storage::XiaoOtaFloorReader;
  for (int fault = 0; fault < 9; ++fault) {
    SCOPED_TRACE(fault);
    QualifiedOriginalFixture q;
    if (fault < 6) {
      uint8_t record[Floor::kRecordBytes];
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.read(0, record, sizeof(record))));
      if (fault == 0) LifecycleFixture::le32(record + 8, 2);
      if (fault == 1) LifecycleFixture::le32(record + 12, 4);
      if (fault == 2) record[20] = 1;
      if (fault == 3) LifecycleFixture::le32(record + 16, 9004);
      LifecycleFixture::le32(record + Floor::kCrcOffset,
                            ::ota::storage::Crc32::computeFinalized(record, Floor::kCrcOffset));
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.eraseSector(0)));
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.program(0, record, sizeof(record))));
      if (fault == 4) ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.program(4096, record, sizeof(record))));
      if (fault == 5) {
        const uint8_t byte = 0;
        ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.program(8191, &byte, 1)));
      }
    }
    if (fault == 6) {
      q.running.hookAt = q.running.reads + 2; q.running.hookContext = &q.f.boot.floor;
      q.running.hook = [](void* context) {
        ASSERT_TRUE(::ota::platform::isOk(static_cast<::ota::platform::FlashRegion*>(context)->eraseSector(0)));
      };
    }
    if (fault == 7) {
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.eraseSector(0)));
      uint32_t numeric_floor = 123;
      ASSERT_TRUE(Floor::readNewestConfirmedCounterFailClosed(q.f.boot.floor, numeric_floor));
      ASSERT_EQ(0u, numeric_floor);
    }
    if (fault == 8) q.f.qualified = false;
    ::ota::storage::XiaoOtaActiveExtentInfo image;
    EXPECT_FALSE(q.original.readOriginalSnapshot(image));
    EXPECT_EQ(0u, image.active_image_extent);
    EXPECT_EQ(0u, q.f.command_flash.programOpCount());
  }
}

TEST(LoraOtaQualifiedOriginal, ExistingImageBoundFactoryAndNonzeroSdkOriginalRemainSupported) {
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1})
    for (bool nonzero_crc : {false, true}) {
      QualifiedOriginalFixture q(board, role);
      q.running.vendorCrcDisabled = !nonzero_crc;
      q.running.sizeOverride = q.f.boot.accessor.image.size();
      if (!nonzero_crc) {
        ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.eraseSector(0)));
        q.f.boot.setFloor(0);
      }
      OtaBoardOriginalImageSnapshot snapshot;
      OtaBoardOriginalSnapshotProvider::Context context;
      ASSERT_TRUE(q.original.read(snapshot, context));
      ASSERT_NE(0, snapshot.computedCrc);
      EXPECT_EQ(OtaBoardOriginalSnapshotProvider::Context::FactoryFloor, context);
      q.f.stage(1); q.f.commit(); q.restoredState(); ASSERT_FALSE(HasFatalFailure());
      ASSERT_TRUE(q.original.read(snapshot, context));
      EXPECT_EQ(OtaBoardOriginalSnapshotProvider::Context::RestoredOriginal, context);
    }
}

TEST(LoraOtaQualifiedOriginal, FactoryConfirmationMustStillBeBlankAfterTheSdkAndMetadataRecheck) {
  QualifiedOriginalFixture q;
  ::ota::test::FakeNorFlash confirm_flash(8192, 4096);
  ::ota::platform::FlashRegion confirm(confirm_flash, 0, 8192);
  q.running.hookAt = q.running.reads + 3; q.running.hookContext = &confirm;
  q.running.hook = [](void* context) {
    const uint8_t byte = 0;
    ASSERT_TRUE(::ota::platform::isOk(static_cast<::ota::platform::FlashRegion*>(context)->program(4095, &byte, 1)));
  };
  EXPECT_FALSE(q.original.ordinaryWritesAllowed(q.f.command, confirm, q.f.fx.sig_verifier, q.f.target, q.f.role));
}

TEST(LoraOtaQualifiedOriginal, ExactSavedZeroSdkRollbackProvesFailedImageAndAnotherAdminsPrecommitAbortAndReupload) {
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1})
    for (auto phase : {::ota::storage::OtaCandidateStore::Phase::Receiving,
                      ::ota::storage::OtaCandidateStore::Phase::Verifying,
                      ::ota::storage::OtaCandidateStore::Phase::Ready}) {
    QualifiedOriginalFixture q(board, role);
    q.f.stage(1); q.f.commit(); ASSERT_FALSE(HasFatalFailure());
    q.restoredState(); ASSERT_FALSE(HasFatalFailure());
    q.attach();
    q.observer->tick(true);
    ASSERT_EQ(usb::UsbOtaPhase::Failed, q.f.fx.integration.reportedPhase());
    q.f.image[12] ^= 1;
    q.f.manifest(2);
    auto& receiver = q.f.fx.integration.leanReceiver();
    ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.begin(q.f.owner.publicKey(), q.f.canonical, q.f.signature, false, false));
    if (phase != ::ota::storage::OtaCandidateStore::Phase::Receiving) {
      for (uint16_t block = 0; block < 2; ++block)
        ASSERT_EQ(usb::UsbOtaResult::Ok, receiver.putBlock(block, q.f.image.data() + block * 84, 84));
      ASSERT_EQ(usb::UsbOtaResult::Pending, receiver.requestSeal());
      if (phase == ::ota::storage::OtaCandidateStore::Phase::Ready) receiver.loop();
    }
    ASSERT_EQ(phase, receiver.status().phase);
    const auto before = q.f.fx.integration.leanReceiver().status();
    uint8_t admin_seed[32] = {0xc3}, message[usb::kAbortSignedBytes], signature[64];
    ::ota::test::Ed25519TestSigner admin(admin_seed);
    q.f.fx.admins.add(admin.publicKey());
    usb::buildAbortSignedMessage(q.f.fx.target_public_key, before.imageHash, before.generation, message);
    admin.sign(message, sizeof(message), signature);
    const auto erases = q.f.command_flash.eraseOpCount();
    ASSERT_EQ(usb::UsbOtaResult::Ok, q.f.fx.integration.leanReceiver().abort(
        admin.publicKey(), signature, before.imageHash, before.generation));
    EXPECT_EQ(erases, q.f.command_flash.eraseOpCount());
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, q.f.fx.integration.leanReceiver().status().phase);
    EXPECT_EQ(0, std::memcmp(before.ownerPublicKey, q.f.fx.integration.leanReceiver().status().ownerPublicKey, 32));
    uint8_t authorization[kOtaAuthorizationFrameBytes];
    const auto authorization_size = encodeOtaAuthorizationFrame(
        q.f.owner.publicKey(), q.f.canonical, q.f.signature, authorization, sizeof(authorization));
    EXPECT_FALSE(q.f.fx.integration.handleReceivedFrame(authorization, authorization_size, 100));
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Aborted, receiver.status().phase);
    q.f.image[24] ^= 1;
    q.f.stage(3, true); ASSERT_FALSE(HasFatalFailure());
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Ready, q.f.fx.integration.leanReceiver().status().phase);
  }
}

TEST(LoraOtaQualifiedOriginal, RestoredZeroSdkNeverAcceptsDifferentRawSdkBackupShaOrUnpairedSidecar) {
  for (int fault = 0; fault < 8; ++fault) {
    QualifiedOriginalFixture q;
    q.f.stage(1); q.f.commit(); q.restoredState(); ASSERT_FALSE(HasFatalFailure());
    if (fault == 0) q.running.bank1 = 0xfe;
    if (fault == 1) q.running.vendorCrcDisabled = false;
    if (fault == 2) q.f.boot.accessor.image[100] ^= 1;
    if (fault == 3) { const uint8_t byte = 0; ASSERT_TRUE(::ota::platform::isOk(q.f.boot.state.program(0x100, &byte, 1))); }
    if (fault == 4) { const uint8_t byte = 0; ASSERT_TRUE(::ota::platform::isOk(q.f.boot.state.program(4095, &byte, 1))); }
    if (fault == 5) q.running.fail = true;
    if (fault == 6) q.running.unusedSdkByte = 1;
    if (fault == 7) {
      uint8_t state[::ota::storage::XiaoOtaStateReader::kRecordBytes], sidecar[88];
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.state.read(0, state, sizeof(state))));
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.state.read(0x100, sidecar, sizeof(sidecar))));
      sidecar[76] ^= 1;
      LifecycleFixture::le32(sidecar + 80, ::ota::storage::Crc32::computeFinalized(sidecar, 80));
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.state.eraseSector(0)));
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.state.program(0, state, sizeof(state))));
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.state.program(0x100, sidecar, sizeof(sidecar))));
    }
    OtaBoardOriginalImageSnapshot snapshot;
    OtaBoardOriginalSnapshotProvider::Context context;
    EXPECT_FALSE(q.original.read(snapshot, context));
    q.attach(); q.observer->tick(true);
    OtaBootLifecycleEvidence evidence;
    ASSERT_TRUE(q.observer->read(true, evidence));
    const uint8_t unknown_hash[32] = {};
    EXPECT_EQ(0, std::memcmp(unknown_hash, evidence.imageHash, sizeof(unknown_hash)));
    EXPECT_EQ(usb::UsbOtaResult::TooLate, q.f.abort());
    EXPECT_EQ(::ota::storage::OtaCandidateStore::Phase::Committed, q.f.fx.integration.leanReceiver().status().phase);
  }

}

TEST(LoraOtaQualifiedOriginal, RestoredSdkProofIsIndependentButMalformedOrPendingCurrentIntentStillBlocksWrites) {
  using Command = ::ota::storage::XiaoOtaCommandRecordV3;
  using State = ::ota::storage::XiaoOtaStateReader;
  for (int fault = 0; fault < 3; ++fault) {
    QualifiedOriginalFixture q;
    q.f.stage(1); q.f.commit(); q.restoredState(); ASSERT_FALSE(HasFatalFailure());
    uint8_t command[Command::kRecordBytes];
    ASSERT_TRUE(Command::readNewest(q.f.command, command));
    if (fault == 0) command[Command::kSignatureOffset] ^= 1;
    if (fault == 1) command[12] ^= 1;
    if (fault == 2) {
      q.f.manifest(2);
      std::memcpy(command + 20, q.f.canonical, sizeof(q.f.canonical));
      std::memcpy(command + Command::kSignatureOffset, q.f.signature, sizeof(q.f.signature));
    }
    LifecycleFixture::le32(command + Command::kCrcOffset,
                          ::ota::storage::Crc32::computeFinalized(command, Command::kCrcOffset));
    ASSERT_TRUE(::ota::platform::isOk(q.f.command.eraseSector(0)));
    ASSERT_TRUE(::ota::platform::isOk(q.f.command.program(0, command, sizeof(command))));
    OtaBoardOriginalImageSnapshot snapshot;
    OtaBoardOriginalSnapshotProvider::Context context;
    ASSERT_TRUE(q.original.read(snapshot, context));
    ASSERT_EQ(OtaBoardOriginalSnapshotProvider::Context::RestoredOriginal, context);
    ::ota::test::FakeNorFlash confirm_flash(8192, 4096);
    ::ota::platform::FlashRegion confirm(confirm_flash, 0, 8192);
    const bool proven = q.original.ordinaryWritesAllowed(
        q.f.command, confirm, q.f.fx.sig_verifier, q.f.target, q.f.role);
    EXPECT_FALSE(proven);
    const auto decision = resolveOtaBoardOriginalStartupDecision(true, State::ReadStatus::Found,
                                                                 State::kPhaseFailedMax, proven);
    Adafruit_LittleFS filesystem;
    PacketBoundaryRtc clock;
    DataStore store(filesystem, clock);
    store.begin(decision.status == OtaBoardStartupDecisionStatus::Normal, false);
    NodePrefs prefs;
    EXPECT_FALSE(store.savePrefs(prefs));
    EXPECT_EQ(0u, filesystem.mounts);
    EXPECT_EQ(0u, filesystem.writes);
  }
}

TEST(LoraOtaQualifiedOriginal, ConfirmedCandidateZeroRemainsLiteralAndWrongZeroNeverUsesTheOriginalException) {
  using State = ::ota::storage::XiaoOtaStateReader;
  using Bridge = ::ota::storage::XiaoOtaActiveExtentBridge;
  QualifiedOriginalFixture q;
  auto& image = q.f.boot.accessor.image;
  const auto crc = Bridge::crc16Compute(image.data(), image.size() - 2);
  image[image.size() - 2] = crc >> 8; image.back() = crc;
  ASSERT_EQ(0, Bridge::crc16Compute(image.data(), image.size()));
  q.running.sizeOverride = image.size();
  ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.eraseSector(0)));
  ::ota::trust::Sha256::hash(image.data(), image.size(), q.f.boot.hash);
  q.f.boot.setFloor(4); q.f.boot.setState(State::kPhaseConfirmed, 4);
  OtaBoardOriginalImageSnapshot snapshot;
  OtaBoardOriginalSnapshotProvider::Context context;
  ASSERT_TRUE(q.original.read(snapshot, context));
  EXPECT_EQ(OtaBoardOriginalSnapshotProvider::Context::Confirmed, context);
  EXPECT_EQ(0, snapshot.computedCrc);
  image[100] ^= 1;
  ASSERT_NE(0, Bridge::crc16Compute(image.data(), image.size()));
  ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.eraseSector(0)));
  ASSERT_TRUE(::ota::platform::isOk(q.f.boot.state.eraseSector(0)));
  ::ota::trust::Sha256::hash(image.data(), image.size(), q.f.boot.hash);
  q.f.boot.setFloor(4); q.f.boot.setState(State::kPhaseConfirmed, 4);
  EXPECT_FALSE(q.original.read(snapshot, context));
  ASSERT_TRUE(::ota::platform::isOk(q.f.boot.state.eraseSector(0)));
  q.f.boot.setState(State::kPhaseTrialBoot, 5);
  EXPECT_FALSE(q.original.read(snapshot, context));
}

TEST(LoraOtaQualifiedOriginal, ProvenFactoryAndRestoredOriginalDriveNormalEarlyDataStoreAndAclWithoutTrialAuthority) {
  using State = ::ota::storage::XiaoOtaStateReader;
  for (uint32_t board : {0x584e3430u, 0x53435031u}) for (uint8_t role : {0, 1}) for (bool restored : {false, true}) {
    QualifiedOriginalFixture q(board, role);
    if (restored) { q.f.stage(1); q.f.commit(); q.restoredState(); q.attach(); }
    ASSERT_FALSE(HasFatalFailure());
    ::ota::test::FakeNorFlash confirm_flash(8192, 4096);
    ::ota::platform::FlashRegion confirm(confirm_flash, 0, 8192);
    uint8_t state[State::kRecordBytes] = {};
    const auto status = State::readNewestWithStatus(q.f.boot.state, state);
    const bool proven = q.original.ordinaryWritesAllowed(q.f.command, confirm, q.f.fx.sig_verifier, board, role);
    ASSERT_TRUE(proven);
    const auto decision = resolveOtaBoardOriginalStartupDecision(true, status,
        status == State::ReadStatus::Found ? State::phase(state) : 0, proven);
    ASSERT_EQ(OtaBoardStartupDecisionStatus::Normal, decision.status);
    Adafruit_LittleFS filesystem;
    ASSERT_EQ(0u, filesystem.mounts);
    ASSERT_TRUE(filesystem.begin());
    PacketBoundaryRtc clock;
    DataStore store(filesystem, clock);
    store.begin(decision.status == OtaBoardStartupDecisionStatus::Normal, false);
    NodePrefs prefs;
    std::strcpy(prefs.node_name, "qualified-original");
    ASSERT_TRUE(store.savePrefs(prefs));
    NodePrefs readback;
    ASSERT_TRUE(store.loadPrefs(readback, true));
    EXPECT_STREQ("qualified-original", readback.node_name);
    stock_acl_test::ClientACL acl;
    ASSERT_NE(nullptr, acl.putClient(mesh::Identity(q.f.owner.publicKey()), PERM_ACL_ADMIN));
    acl.save(&filesystem);
    EXPECT_TRUE(filesystem.exists("/s_contacts"));
    EXPECT_FALSE(store.formatFileSystem());
    EXPECT_EQ(0u, filesystem.formats);
    EXPECT_EQ(0u, confirm_flash.programOpCount());
    EXPECT_EQ(0u, confirm_flash.eraseOpCount());
  }
}

TEST(LoraOtaQualifiedOriginal, PendingMalformedAndUnexplainedHistoryNeverUnlockNormalOriginalWrites) {
  using State = ::ota::storage::XiaoOtaStateReader;
  for (int fault = 0; fault < 7; ++fault) {
    QualifiedOriginalFixture q;
    ::ota::test::FakeNorFlash confirm_flash(8192, 4096);
    ::ota::platform::FlashRegion confirm(confirm_flash, 0, 8192);
    const uint8_t byte = 0;
    if (fault == 0) { q.f.stage(1); q.f.commit(); }
    if (fault == 1) ASSERT_TRUE(::ota::platform::isOk(q.f.command.program(0, &byte, 1)));
    if (fault == 2) ASSERT_TRUE(::ota::platform::isOk(q.f.command.program(4095, &byte, 1)));
    if (fault == 3) ASSERT_TRUE(::ota::platform::isOk(confirm.program(4095, &byte, 1)));
    if (fault == 4) q.f.boot.setState(State::kPhaseTrialBoot);
    if (fault == 5) q.f.boot.setState(4);
    if (fault == 6) {
      ASSERT_TRUE(::ota::platform::isOk(q.f.boot.floor.eraseSector(0)));
      q.f.boot.setFloor(4);
    }
    const bool proven = q.original.ordinaryWritesAllowed(
        q.f.command, confirm, q.f.fx.sig_verifier, q.f.target, q.f.role);
    EXPECT_FALSE(proven);
    uint8_t state[State::kRecordBytes] = {};
    const auto status = State::readNewestWithStatus(q.f.boot.state, state);
    const auto decision = resolveOtaBoardOriginalStartupDecision(true, status,
        status == State::ReadStatus::Found ? State::phase(state) : 0, proven);
    EXPECT_NE(OtaBoardStartupDecisionStatus::Normal, decision.status);
    Adafruit_LittleFS filesystem;
    PacketBoundaryRtc clock;
    DataStore store(filesystem, clock);
    store.begin(decision.status == OtaBoardStartupDecisionStatus::Normal, false);
    NodePrefs prefs;
    EXPECT_FALSE(store.savePrefs(prefs));
    EXPECT_EQ(0u, filesystem.mounts);
    EXPECT_EQ(0u, filesystem.writes);
  }
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
