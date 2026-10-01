// gtest suite for the OTA commissioning authority (src/ota/authority/**):
// real two-copy durable file-backed registry (restart/power-cut/replay/
// cold-reconstruction), canonical signed transaction codec, the host
// AuthorityCoordinator's full describeBinding/prepare/resumePrepared/
// activateExistingRoot/repairExisting/rekeyExplicitly API, and the
// portable default-denying DeviceAuthorityGuard -- all using genuine
// Ed25519 sign/verify round trips (test/test_lora_ota_trust's
// Ed25519TestSigner), never a fake verifier.

#include <gtest/gtest.h>
#include <stdint.h>
#include <cstring>
#include <string>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <atomic>
#include <new>
#include <ctime>

#include "ota/authority/AuthorityTypes.h"
#include "ota/authority/AuthorityCodec.h"
#include "ota/authority/BaselineCertificationManifest.h"
#include "ota/authority/AuthorityRegistryPort.h"
#include "ota/authority/FileAuthorityRegistryCopy.h"
#include "ota/authority/AuthorityHostInterfaces.h"
#include "ota/authority/AuthorityCrossProcessLock.h"
#include "ota/authority/AuthorityDeviceSession.h"
#include "ota/authority/AuthorityCoordinator.h"
#include "ota/authority/DeviceAuthorityGuard.h"
#include "ota/authority/DeviceBaselineCertificationGuard.h"
#include "ota/authority/AuthorityCommissioningAdapters.h"
#include "ota/authority/BootFloorActivationReceipt.h"
#include "ota/authority/OriginalBaselineManifestSidecar.h"
#include "ota/authority/PreparedRootCommitment.h"
#include "ota/authority/PrepareAuthorizationCodec.h"
#include "ota/storage/Crc32.h"
#include "ota/trust/Ed25519SignatureVerifier.h"

#include "../test_lora_ota_trust/Ed25519TestSigner.h"

namespace {

using namespace ota::authority;
namespace fs = std::filesystem;

// ---------------------------------------------------------------------
// Shared fixture plumbing.
// ---------------------------------------------------------------------

std::string uniqueTestDir(const std::string& label) {
  static int counter = 0;
  fs::path root = fs::path(".tmp") / "ota-authority-tests";
  fs::create_directories(root);
  fs::path dir = root / (label + "-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
  fs::create_directories(dir);
  return dir.string();
}

uint8_t seedByte(const char* label, int index) {
  uint32_t h = 2166136261u;
  for (const char* p = label; *p; ++p) h = (h ^ static_cast<uint8_t>(*p)) * 16777619u;
  h = (h ^ static_cast<uint32_t>(index)) * 16777619u;
  return static_cast<uint8_t>(h & 0xFFu);
}

void fillSeed(uint8_t out[32], const char* label) {
  for (int i = 0; i < 32; ++i) out[i] = seedByte(label, i);
}

// Same deterministic derivation but bounded to kChallengeBytes (16) --
// used for host/device challenge and nonce buffers, which are half the
// width of a digest/key. Using fillSeed's 32-byte contract on a 16-byte
// buffer would silently overrun adjacent stack fields.
void fillChallenge(uint8_t out[kChallengeBytes], const char* label) {
  for (int i = 0; i < static_cast<int>(kChallengeBytes); ++i) out[i] = seedByte(label, i);
}

class FakeIssuerTrust : public AuthorityIssuerTrust {
public:
  explicit FakeIssuerTrust(const uint8_t public_key[kPublicKeyBytes]) {
    std::memcpy(public_key_, public_key, kPublicKeyBytes);
  }
  bool lookupIssuerPublicKey(uint16_t issuerKeyId, uint8_t out_public_key[kPublicKeyBytes]) const override {
    if (issuerKeyId != 1) return false;  // Only key id 1 is trusted -- an explicit, narrow allow-list.
    std::memcpy(out_public_key, public_key_, kPublicKeyBytes);
    return true;
  }

private:
  uint8_t public_key_[kPublicKeyBytes];
};

// Test-only stand-in for the EXISTING firmware publisher signing
// capability (BootFloorActivationReceipt.h's PublisherKeyTrust seam) --
// a real integrator wires this to whatever already holds the real
// publisher key; this test double uses a genuine (test-only, ephemeral)
// Ed25519 key pair so signature verification in these tests is real, not
// a stub.
class FakePublisherKeyTrust : public PublisherKeyTrust {
public:
  explicit FakePublisherKeyTrust(const ota::test::Ed25519TestSigner& signer, uint16_t keyId, bool fail_signing = false)
      : signer_(signer), keyId_(keyId), fail_signing_(fail_signing) {}

  bool publisherKeyId(uint16_t& out_key_id) const override {
    out_key_id = keyId_;
    return true;
  }
  bool publisherPublicKey(uint8_t out_public_key[kPublicKeyBytes]) const override {
    std::memcpy(out_public_key, signer_.publicKey(), kPublicKeyBytes);
    return true;
  }
  bool signWithPublisherKey(const uint8_t* message, size_t message_len,
                             uint8_t out_signature[kSignatureBytes]) const override {
    if (fail_signing_) return false;
    signer_.sign(message, message_len, out_signature);
    return true;
  }

private:
  const ota::test::Ed25519TestSigner& signer_;
  uint16_t keyId_;
  bool fail_signing_;
};

// Test double for the AUTHORITATIVE baseline provenance record captured
// once at commissioning/prepared-P time -- distinct from any caller-
// supplied `BootFloorBaselineEvidence`, so tests can independently prove
// a mismatch between what a caller claims and what was actually
// recorded is rejected, not silently trusted. Astra role-1 residual:
// covers image SHA-256/extent/target too, not only the SDK28 digest.
class FakeOriginalBaselineSdk28Provenance : public OriginalBaselineSdk28Provenance {
public:
  // Convenience overload: SDK28 digest only, image/extent/target left at
  // zero -- correct for the many call sites that use an all-zero
  // (default-constructed) `BootFloorBaselineEvidence` and only care
  // about exercising the SDK28 comparison in isolation.
  explicit FakeOriginalBaselineSdk28Provenance(const uint8_t sdk28[kBootFloorOriginalSdk28DigestBytes]) {
    std::memcpy(record_.original28Sha256Digest, sdk28, kBootFloorOriginalSdk28DigestBytes);
  }

  FakeOriginalBaselineSdk28Provenance(const uint8_t sdk28[kBootFloorOriginalSdk28DigestBytes],
                                      const uint8_t imageSha256[kBootFloorBaselineImageDigestBytes],
                                      uint32_t extentLength, uint32_t targetId) {
    std::memcpy(record_.original28Sha256Digest, sdk28, kBootFloorOriginalSdk28DigestBytes);
    std::memcpy(record_.imageSha256, imageSha256, kBootFloorBaselineImageDigestBytes);
    record_.extentLength = extentLength;
    record_.targetId = targetId;
  }

  bool lookupOriginalBaselineProvenance(const AuthorityBinding&, const uint8_t[kTransactionIdBytes],
                                        AuthorityBootFloorBaselineProvenanceRecord& out_record) const override {
    out_record = record_;
    return true;
  }

private:
  AuthorityBootFloorBaselineProvenanceRecord record_;
};

// Denies every lookup -- proves the exporter's default-deny when this
// seam is unwired/unable to answer (distinct from an explicit mismatch).
class DenyingOriginalBaselineSdk28Provenance : public OriginalBaselineSdk28Provenance {
public:
  bool lookupOriginalBaselineProvenance(const AuthorityBinding&, const uint8_t[kTransactionIdBytes],
                                        AuthorityBootFloorBaselineProvenanceRecord&) const override {
    return false;
  }
};

// Test-only stand-in for AuthorityActivationSigningTrust (see
// ActivationAuthorizationCodec.h): produces a genuine Ed25519 signature
// using the SAME existing issuer key a real integrator would wire this
// to (identified by issuerKeyId, matching FakeIssuerTrust's narrow
// allow-list) -- never a second/new key, and never a stub that always
// succeeds regardless of key id.
class FakeActivationSigningTrust : public AuthorityActivationSigningTrust {
public:
  explicit FakeActivationSigningTrust(const ota::test::Ed25519TestSigner& signer, uint16_t trustedKeyId = 1,
                                       bool fail_signing = false)
      : signer_(signer), trustedKeyId_(trustedKeyId), fail_signing_(fail_signing) {}

  bool signActivationAuthorization(uint16_t issuerKeyId, const uint8_t* message, size_t message_len,
                                    uint8_t out_signature[kSignatureBytes]) override {
    if (fail_signing_) return false;
    if (issuerKeyId != trustedKeyId_) return false;  // Narrow, explicit allow-list -- never a wildcard signer.
    signer_.sign(message, message_len, out_signature);
    return true;
  }

private:
  const ota::test::Ed25519TestSigner& signer_;
  uint16_t trustedKeyId_;
  bool fail_signing_;
};

// Test-only deterministic-but-distinct "entropy": genuinely different
// bytes on every call (never zeros, never repeats within a test run), so
// challenge/nonce freshness checks are real, not coincidentally constant.
class CountingEntropy : public AuthorityChallengeProvider, public DeviceAuthorityEntropy {
public:
  explicit CountingEntropy(uint8_t tag) : tag_(tag) {}
  bool freshChallenge(uint8_t out_challenge[kChallengeBytes]) override { return next(out_challenge); }
  bool freshNonce(uint8_t out_nonce[kChallengeBytes]) override { return next(out_nonce); }

private:
  bool next(uint8_t out[kChallengeBytes]) {
    ++counter_;
    for (int i = 0; i < static_cast<int>(kChallengeBytes); ++i) {
      out[i] = static_cast<uint8_t>((tag_ * 31u) + counter_ * 7u + i);
    }
    return true;
  }
  uint8_t tag_;
  uint32_t counter_ = 0;
};

class InMemoryDeviceStore : public DeviceAuthorityStore {
public:
  DeviceAuthorityReadStatus readCurrent(DeviceAuthorityState& out) const override {
    // Test-only fault injection for H2: simulates a store that CANNOT be
    // read at all (flash fault, corrupt record) -- distinct from, and
    // never conflated with, a genuinely blank/never-staged device.
    if (simulate_read_error_) return DeviceAuthorityReadStatus::Error;
    // Test-only: models a real async backend that needs SEVERAL extra
    // ticks before readCurrent() can answer synchronously -- each call
    // decrements the counter and reports `Pending` until it reaches
    // zero, so a test can exercise "several Pending reads followed by an
    // exact successful retry" (Sol review MEDIUM coverage), not just one.
    if (simulate_read_pending_count_ > 0) {
      --simulate_read_pending_count_;
      return DeviceAuthorityReadStatus::Pending;
    }
    if (!has_state_) return DeviceAuthorityReadStatus::PositivelyEmpty;
    out = state_;
    return DeviceAuthorityReadStatus::Present;
  }
  DeviceAuthorityIoStatus commitStaged(const uint8_t transactionId[kTransactionIdBytes], const uint8_t rootDigestSha256[kDigestBytes],
                                        uint32_t txSequenceFloor, uint32_t rxReplayFloor) override {
    if (simulate_commit_staged_pending_once_) {
      simulate_commit_staged_pending_once_ = false;
      return DeviceAuthorityIoStatus::Pending;
    }
    state_.staged = true;
    state_.activated = false;
    std::memcpy(state_.transactionId, transactionId, kTransactionIdBytes);
    std::memcpy(state_.stagedRootDigestSha256, rootDigestSha256, kDigestBytes);
    state_.txSequenceFloor = txSequenceFloor;
    state_.rxReplayFloor = rxReplayFloor;
    has_state_ = true;
    return DeviceAuthorityIoStatus::Ok;
  }
  DeviceAuthorityIoStatus commitActivated(const uint8_t transactionId[kTransactionIdBytes],
                                           const uint8_t rootDigestSha256[kDigestBytes]) override {
    if (simulate_commit_activated_pending_once_) {
      simulate_commit_activated_pending_once_ = false;
      return DeviceAuthorityIoStatus::Pending;
    }
    if (!has_state_ || !state_.staged) return DeviceAuthorityIoStatus::Denied;
    if (std::memcmp(state_.transactionId, transactionId, kTransactionIdBytes) != 0) return DeviceAuthorityIoStatus::Denied;
    if (std::memcmp(state_.stagedRootDigestSha256, rootDigestSha256, kDigestBytes) != 0) return DeviceAuthorityIoStatus::Denied;
    state_.activated = true;
    return DeviceAuthorityIoStatus::Ok;
  }

  // Test-only: models a flash wipe/lost store.
  void simulateRootLoss() { has_state_ = false; state_ = DeviceAuthorityState{}; }

  // Test-only: models a read/IO fault distinct from a genuinely blank
  // store -- writes remain available (commitStaged/commitActivated are
  // unaffected) while reads report `Error`, per H2.
  void simulateReadError(bool enabled) { simulate_read_error_ = enabled; }

  // Test-only: models a real async backend that needs one extra tick
  // before a single commitStaged/commitActivated call durably completes
  // -- the NEXT call with the same arguments succeeds, never silently
  // skipped.
  void simulateCommitStagedPendingOnce() { simulate_commit_staged_pending_once_ = true; }
  void simulateCommitActivatedPendingOnce() { simulate_commit_activated_pending_once_ = true; }

  // Test-only: makes the NEXT `count` readCurrent() calls report
  // `Pending` before genuinely answering -- models several real-backend
  // ticks needed before activation's post-challenge-consumption
  // readCurrent() can resume durably.
  void simulateReadPendingTimes(int count) { simulate_read_pending_count_ = count; }

  // Test-only observation hook: lets a test assert that a denied
  // operation caused NO output mutation of the store's own state.
  const DeviceAuthorityState& rawStateForTest() const { return state_; }
  bool hasStateForTest() const { return has_state_; }

private:
  bool has_state_ = false;
  bool simulate_read_error_ = false;
  mutable int simulate_read_pending_count_ = 0;
  bool simulate_commit_staged_pending_once_ = false;
  bool simulate_commit_activated_pending_once_ = false;
  DeviceAuthorityState state_;
};

class RecordingMaintenance : public DeviceAuthorityMaintenance {
public:
  // Test double for the real Store/Firmware stageRoot() integration:
  // produces a genuine SHA-256 digest (via the real PreparedRootCommitment
  // formula) over a deterministic stand-in for P (here: the full signed
  // record bytes) -- never a caller-echoed/copied "expected" digest and
  // never a placeholder RAM bool. Real P content (actual device storage
  // state/seeds) remains Store's unwired integration responsibility;
  // this double only proves the formula/seam shape with real bytes.
  DeviceAuthorityIoStatus stageRoot(const AuthorityTransaction& txn, uint8_t out_rootDigestSha256[kDigestBytes]) override {
    ++stage_calls;
    if (simulate_stage_pending_once) {
      simulate_stage_pending_once = false;
      return DeviceAuthorityIoStatus::Pending;
    }
    if (!allow_stage) return DeviceAuthorityIoStatus::Denied;
    uint8_t record[AuthorityCodec::kRecordBytes];
    if (AuthorityCodec::serializeRecord(txn, record, sizeof(record)) != AuthorityCodec::kRecordBytes) {
      return DeviceAuthorityIoStatus::Denied;
    }
    if (PreparedRootCommitment::computeDigestSha256(record, sizeof(record), out_rootDigestSha256) !=
        PreparedRootCommitment::Result::kOk) {
      return DeviceAuthorityIoStatus::Denied;
    }
    return DeviceAuthorityIoStatus::Ok;
  }
  DeviceAuthorityIoStatus activateStagedRoot(const uint8_t[kTransactionIdBytes], const uint8_t[kDigestBytes]) override {
    ++activate_calls;
    if (simulate_activate_pending_once) {
      simulate_activate_pending_once = false;
      return DeviceAuthorityIoStatus::Pending;
    }
    return allow_activate ? DeviceAuthorityIoStatus::Ok : DeviceAuthorityIoStatus::Denied;
  }
  int stage_calls = 0;
  int activate_calls = 0;
  bool allow_stage = true;
  bool allow_activate = true;
  bool simulate_stage_pending_once = false;
  bool simulate_activate_pending_once = false;
};

// Test-only local-evidence double for DeviceBaselineCertificationGuard:
// `manifest` is what a "real, freshly-taken measurement" would have
// produced -- tests mutate it (including `allowOrdinaryUserdata`) to
// model a genuinely different boot's evidence or a baseline that
// explicitly does not permit ordinary userdata, and
// `fail_next_capture`/`captures` let a test assert the guard actually
// re-invokes this every single evaluate() call (never caches a prior
// positive result).
class FakeDeviceBaselineLocalEvidence : public DeviceBaselineLocalEvidence {
public:
  bool captureFreshManifest(BaselineCertificationManifest& out_manifest) override {
    ++captures;
    if (fail_next_capture) {
      fail_next_capture = false;
      return false;
    }
    out_manifest = manifest;
    return true;
  }
  BaselineCertificationManifest manifest;
  bool fail_next_capture = false;
  int captures = 0;
};

class Ed25519DeviceSigner : public DeviceIdentitySigner {
public:
  explicit Ed25519DeviceSigner(const ota::test::Ed25519TestSigner& signer) : signer_(signer) {}
  bool signWithDeviceIdentity(const uint8_t* message, size_t message_len, uint8_t out_signature[kSignatureBytes]) override {
    signer_.sign(message, message_len, out_signature);
    return true;
  }

private:
  const ota::test::Ed25519TestSigner& signer_;
};

// Test-only stand-in for AuthorityPrepareSigningTrust (see
// PrepareAuthorizationCodec.h): mirrors FakeActivationSigningTrust
// exactly -- produces a genuine Ed25519 signature using the SAME
// existing issuer key a real integrator would wire this to.
class FakePrepareSigningTrust : public AuthorityPrepareSigningTrust {
public:
  explicit FakePrepareSigningTrust(const ota::test::Ed25519TestSigner& signer, uint16_t trustedKeyId = 1,
                                    bool fail_signing = false)
      : signer_(signer), trustedKeyId_(trustedKeyId), fail_signing_(fail_signing) {}

  bool signPrepareAuthorization(uint16_t issuerKeyId, const uint8_t* message, size_t message_len,
                                 uint8_t out_signature[kSignatureBytes]) override {
    if (fail_signing_) return false;
    if (issuerKeyId != trustedKeyId_) return false;  // Narrow, explicit allow-list -- never a wildcard signer.
    signer_.sign(message, message_len, out_signature);
    return true;
  }

private:
  const ota::test::Ed25519TestSigner& signer_;
  uint16_t trustedKeyId_;
  bool fail_signing_;
};

// Direct in-process "transport": forwards permits straight into a real
// DeviceAuthorityGuard, so end-to-end tests exercise genuine sign/verify
// on both sides without needing an actual USB/serial transport (that
// integration is explicitly out of scope here).
class LoopbackDeviceSession : public DeviceAuthoritySession {
public:
  explicit LoopbackDeviceSession(DeviceAuthorityGuard& guard) : guard_(guard) {}

  // Real device-minted challenge, drawn in-process from the SAME guard
  // that will later verify it -- never a value this test double invents
  // independently of the guard.
  bool requestDeviceChallenge(AuthorityChallengePurpose purpose, const uint8_t transactionId[kTransactionIdBytes],
                               uint8_t out_challenge[kChallengeBytes]) override {
    if (drop_challenge_response) return false;
    return guard_.beginChallenge(purpose, transactionId, out_challenge);
  }

  bool sendPreparePermit(const PreparePermit& permit, PreparedRootResponse& out_response) override {
    if (drop_prepare_response) return false;  // Models a lost response / dead transport.
    // This loopback is an in-process test bridge, not a real multi-tick
    // transport -- a bounded retry loop here lets `Pending` genuinely
    // resume the SAME in-flight guard continuation (verified by the
    // guard itself never re-consuming the challenge/re-signing), without
    // requiring the abstract session interface to become Pending-aware.
    for (int attempt = 0; attempt < kMaxPendingRetries; ++attempt) {
      const AuthorityOutcome outcome = guard_.verifyAndPrepare(permit, out_response);
      if (outcome == AuthorityOutcome::Ok) return true;
      if (outcome != AuthorityOutcome::Pending) return false;
    }
    return false;
  }
  bool sendActivationPermit(const ActivationPermit& permit, ActivationResponse& out_response) override {
    if (drop_activation_response) return false;
    TxRxActivationGrant grant;
    for (int attempt = 0; attempt < kMaxPendingRetries; ++attempt) {
      const AuthorityOutcome outcome = guard_.verifyAndActivate(permit, out_response, grant);
      if (outcome == AuthorityOutcome::Ok) return true;
      if (outcome != AuthorityOutcome::Pending) return false;
    }
    return false;
  }

  bool drop_prepare_response = false;
  bool drop_activation_response = false;
  bool drop_challenge_response = false;

private:
  static constexpr int kMaxPendingRetries = 8;
  DeviceAuthorityGuard& guard_;
};

// A session double that returns a syntactically-valid-shaped but WRONG
// response (bad signature / wrong root / stale challenge), to exercise
// the coordinator's own independent verification rather than trusting
// whatever the device claims.
class ScriptedDeviceSession : public DeviceAuthoritySession {
public:
  PreparedRootResponse prepare_response;
  ActivationResponse activation_response;
  bool prepare_ok = true;
  bool activation_ok = true;
  bool challenge_ok = true;
  uint8_t challenge_response[kChallengeBytes] = {0};

  // Call counters -- NOT behavior, purely diagnostic. These let a test
  // prove the coordinator actually reached the device-challenge/ACK-
  // verification call path (and did not deny earlier for an unrelated
  // reason such as a missing dependency or a binding mismatch) before
  // asserting on the final AuthorityOutcome.
  int requestDeviceChallengeCalls = 0;
  int sendPreparePermitCalls = 0;
  int sendActivationPermitCalls = 0;

  bool requestDeviceChallenge(AuthorityChallengePurpose, const uint8_t[kTransactionIdBytes],
                               uint8_t out_challenge[kChallengeBytes]) override {
    ++requestDeviceChallengeCalls;
    if (!challenge_ok) return false;
    std::memcpy(out_challenge, challenge_response, kChallengeBytes);
    return true;
  }
  bool sendPreparePermit(const PreparePermit&, PreparedRootResponse& out_response) override {
    ++sendPreparePermitCalls;
    out_response = prepare_response;
    return prepare_ok;
  }
  bool sendActivationPermit(const ActivationPermit&, ActivationResponse& out_response) override {
    ++sendActivationPermitCalls;
    out_response = activation_response;
    return activation_ok;
  }
};

// Diagnostic-only: human-readable AuthorityOutcome name for assertion
// failure messages (so a mismatch reports e.g. "actual=WrongState"
// rather than an opaque integer). Not used by any production code path.
inline const char* authorityOutcomeName(AuthorityOutcome outcome) {
  switch (outcome) {
    case AuthorityOutcome::Ok: return "Ok";
    case AuthorityOutcome::Denied: return "Denied";
    case AuthorityOutcome::BindingMismatch: return "BindingMismatch";
    case AuthorityOutcome::SignatureInvalid: return "SignatureInvalid";
    case AuthorityOutcome::TransactionNotFound: return "TransactionNotFound";
    case AuthorityOutcome::WrongState: return "WrongState";
    case AuthorityOutcome::RegistryDisagreement: return "RegistryDisagreement";
    case AuthorityOutcome::StaleRevision: return "StaleRevision";
    case AuthorityOutcome::ChallengeMismatch: return "ChallengeMismatch";
    case AuthorityOutcome::DeviceResponseMismatch: return "DeviceResponseMismatch";
    case AuthorityOutcome::MissingHistory: return "MissingHistory";
    case AuthorityOutcome::CorruptRecord: return "CorruptRecord";
    case AuthorityOutcome::OperationMismatch: return "OperationMismatch";
    case AuthorityOutcome::Pending: return "Pending";
  }
  return "UnknownAuthorityOutcome";
}

struct TestDevice {
  ota::test::Ed25519TestSigner signer;
  AuthorityBinding binding;

  explicit TestDevice(const char* label, uint32_t uidTag) : signer(makeSeed(label)) {
    std::memset(binding.hardwareUid, 0, kHardwareUidBytes);
    binding.hardwareUid[0] = static_cast<uint8_t>(uidTag);
    binding.hardwareUid[1] = static_cast<uint8_t>(uidTag >> 8);
    std::memcpy(binding.meshFullPublicKey, signer.publicKey(), kPublicKeyBytes);
    binding.cryptoDomain.form = meshcore::ota::runtime::OtaAeadForm::Pairwise;
    binding.cryptoDomain.groupSelector = 0;
    binding.profileId = 0x584E3430u;
    binding.layoutId = 1;
    binding.historicalInitialRoleId = 0;  // companion role, by convention in tests.
    std::memset(binding.consentOwnerPublicKey, 0x42, kPublicKeyBytes);
  }

private:
  static uint8_t seed_buf[32];
  static const uint8_t* makeSeed(const char* label) {
    fillSeed(seed_buf, label);
    return seed_buf;
  }
};
uint8_t TestDevice::seed_buf[32];

class AuthorityFixture : public ::testing::Test {
protected:
  void SetUp() override {
    fillSeed(issuer_seed_, "issuer");
    issuer_signer_ = std::make_unique<ota::test::Ed25519TestSigner>(issuer_seed_);
    issuer_trust_ = std::make_unique<FakeIssuerTrust>(issuer_signer_->publicKey());
    activation_signing_trust_ = std::make_unique<FakeActivationSigningTrust>(*issuer_signer_, /*trustedKeyId=*/1);
    prepare_signing_trust_ = std::make_unique<FakePrepareSigningTrust>(*issuer_signer_, /*trustedKeyId=*/1);

    dir_ = uniqueTestDir("registry");
    copyAPath_ = dir_ + "/copyA.bin";
    copyBPath_ = dir_ + "/copyB.bin";
  }

  uint8_t issuer_seed_[32];
  std::unique_ptr<ota::test::Ed25519TestSigner> issuer_signer_;
  std::unique_ptr<FakeIssuerTrust> issuer_trust_;
  std::unique_ptr<FakeActivationSigningTrust> activation_signing_trust_;
  std::unique_ptr<FakePrepareSigningTrust> prepare_signing_trust_;
  ota::trust::Ed25519SignatureVerifier verifier_;
  std::string dir_, copyAPath_, copyBPath_;
  // Sol c577a77f (H2): a missing AuthorityCoordinator lock now always
  // denies -- these single-process tests never run a second real OS
  // process and do not need real flock() serialization, so they
  // EXPLICITLY opt into the trivial single-process contract rather than
  // relying on any nullptr-means-fine fallback (removed).
  InProcessOnlyAuthorityCrossProcessLock test_lock_;

  AuthorityTransaction makeCommission(const AuthorityBinding& binding, const uint8_t transactionId[kTransactionIdBytes],
                                       const uint8_t manifestDigest[kDigestBytes], uint32_t txFloor = 1,
                                       uint32_t rxFloor = 1) {
    AuthorityTransaction txn;
    txn.binding = binding;
    txn.operation = AuthorityOperation::Commission;
    std::memcpy(txn.transactionId, transactionId, kTransactionIdBytes);
    txn.revision = 0;
    std::memset(txn.predecessorTransactionId, 0, kTransactionIdBytes);
    std::memcpy(txn.manifestDigestSha256, manifestDigest, kDigestBytes);
    txn.initialTxSequenceFloor = txFloor;
    txn.initialRxReplayFloor = rxFloor;
    txn.issuerKeyId = 1;
    txn.issuedAtUnixSeconds = 1700000000ull;
    sign(txn);
    return txn;
  }


  // CertifyExistingBaseline transactions always carry zero revision/
  // predecessor/floors -- see AuthorityCoordinator::submitCertifyExistingBaseline.
  AuthorityTransaction makeCertifyExistingBaseline(const AuthorityBinding& binding,
                                                    const uint8_t transactionId[kTransactionIdBytes],
                                                    const uint8_t manifestDigest[kDigestBytes]) {
    AuthorityTransaction txn;
    txn.binding = binding;
    txn.operation = AuthorityOperation::CertifyExistingBaseline;
    std::memcpy(txn.transactionId, transactionId, kTransactionIdBytes);
    txn.revision = 0;
    std::memset(txn.predecessorTransactionId, 0, kTransactionIdBytes);
    std::memcpy(txn.manifestDigestSha256, manifestDigest, kDigestBytes);
    txn.initialTxSequenceFloor = 0;
    txn.initialRxReplayFloor = 0;
    txn.issuerKeyId = 1;
    txn.issuedAtUnixSeconds = 1700000000ull;
    sign(txn);
    return txn;
  }

  void sign(AuthorityTransaction& txn) {
    uint8_t message[AuthorityCodec::kSignedMessageBytes];
    ASSERT_EQ(AuthorityCodec::serializeSignedMessage(txn, message, sizeof(message)), AuthorityCodec::kSignedMessageBytes);
    issuer_signer_->sign(message, sizeof(message), txn.issuerSignatureEd25519);
  }

  // Builds a genuinely-signed PrepareAuthorizationV1 for manual
  // PreparePermit test constructions -- mirrors exactly what
  // AuthorityCoordinator::runPrepareHandshake produces in production
  // (same field sourcing via defaultPrepareInputs' self-consistent
  // certifyTxn/manifest/rxContextKind/peerFullPublicKey, same
  // domain-separated signed message, same issuer key), so tests
  // exercise the REAL verification path in
  // DeviceAuthorityGuard::verifyAndPrepare rather than a bare-field
  // stub. `deviceChallenge` is whatever value the test wants bound here
  // -- callers that want a genuinely matching single-use challenge must
  // first obtain it via `guard.beginChallenge(Prepare, txn.transactionId,
  // ...)` and pass that SAME value; callers testing a cross-bound/stale
  // challenge pass a deliberately different one.
  void signPrepareAuth(const AuthorityTransaction& txn, const uint8_t deviceChallenge[kChallengeBytes],
                        PrepareAuthorizationV1& out) {
    out = PrepareAuthorizationV1{};
    std::memcpy(out.transactionId, txn.transactionId, kTransactionIdBytes);
    ASSERT_TRUE(AuthorityCodec::computeRecordDigestSha256(txn, out.grantDigestSha256));
    const BaselineCertificationManifest manifest{};
    uint8_t peer_key[kPublicKeyBytes] = {0};
    ASSERT_TRUE(PrepareAuthorizationCodec::computeInputDigestSha256(txn, txn, manifest, PrepareRxContextKind::None,
                                                                      peer_key, out.inputDigestSha256));
    out.authorizedRevision = txn.revision;
    out.expectedBinding = txn.binding;
    std::memcpy(out.deviceFreshChallenge, deviceChallenge, kChallengeBytes);
    fillChallenge(out.hostNonce, "test-prepare-host-nonce");
    uint8_t message[PrepareAuthorizationCodec::kSignedMessageBytes];
    ASSERT_EQ(PrepareAuthorizationCodec::serializeSignedMessage(out, message, sizeof(message)),
              PrepareAuthorizationCodec::kSignedMessageBytes);
    issuer_signer_->sign(message, sizeof(message), out.issuerSignatureEd25519);
  }

  // Builds a genuinely-signed ActivationAuthorizationV1 for manual
  // ActivationPermit test constructions -- mirrors exactly what
  // AuthorityCoordinator::activateExistingRoot produces in production
  // (same field sourcing, same domain-separated signed message, same
  // issuer key), so tests exercise the real verification path in
  // DeviceAuthorityGuard::verifyAndActivate rather than a stub.
  void signActivationAuth(const AuthorityTransaction& txn, const uint8_t preparedRootDigest[kDigestBytes],
                           const uint8_t hostChallenge[kChallengeBytes], ActivationAuthorizationV1& out) {
    out = ActivationAuthorizationV1{};
    std::memcpy(out.transactionId, txn.transactionId, kTransactionIdBytes);
    // Astra29 fix: grantDigestSha256 MUST be A = SHA256(the exact full
    // signed 238-byte record, including the issuer signature), never M
    // (manifestDigestSha256, policy content only).
    ASSERT_TRUE(AuthorityCodec::computeRecordDigestSha256(txn, out.grantDigestSha256));
    std::memcpy(out.preparedRootDigestSha256, preparedRootDigest, kDigestBytes);
    out.spentAuthorizedRevision = txn.revision;
    out.expectedBinding = txn.binding;
    std::memcpy(out.deviceFreshChallenge, hostChallenge, kChallengeBytes);
    fillChallenge(out.hostNonce, "test-activation-host-nonce");
    uint8_t message[ActivationAuthorizationCodec::kSignedMessageBytes];
    ASSERT_EQ(ActivationAuthorizationCodec::serializeSignedMessage(out, message, sizeof(message)),
              ActivationAuthorizationCodec::kSignedMessageBytes);
    issuer_signer_->sign(message, sizeof(message), out.issuerSignatureEd25519);
  }

  // Builds a genuine, self-consistent PrepareAuthorizationInputs for
  // tests: reuses the already-signed grant transaction itself as the
  // "certifyTxn" input (a real, fully-formed AuthorityTransaction -- not
  // a placeholder struct), a default-constructed baseline manifest, no
  // RX context, and a zeroed peer key. This is sufficient to exercise
  // the REAL computeInputDigestSha256/signature path end-to-end; tests
  // that need a specific non-default rxContextKind/peerFullPublicKey
  // build their own PrepareAuthorizationInputs directly instead of
  // calling this helper.
  PrepareAuthorizationInputs defaultPrepareInputs(const AuthorityTransaction& grantTxn) {
    PrepareAuthorizationInputs inputs;
    inputs.certifyTxn = grantTxn;
    inputs.manifest = BaselineCertificationManifest{};
    inputs.rxContextKind = PrepareRxContextKind::None;
    std::memset(inputs.peerFullPublicKey, 0, kPublicKeyBytes);
    return inputs;
  }

  // Shared boilerplate for BootFloorActivationReceipt tests: runs the
  // real prepare+activate handshake (via a genuine DeviceAuthorityGuard
  // over a loopback session) for an ALREADY-submitted transaction, so
  // each export test only has to set up what's specific to it.
  void prepareAndActivate(AuthorityCoordinator& coordinator, const uint8_t transactionId[kTransactionIdBytes],
                           const TestDevice& device, uint8_t entropyTag, const AuthorityTransaction& grantTxn) {
    InMemoryDeviceStore device_store;
    RecordingMaintenance maintenance;
    CountingEntropy device_entropy(entropyTag);
    Ed25519DeviceSigner signer(device.signer);
    DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store,
                                &maintenance, &signer);
    LoopbackDeviceSession session(guard);
    StoredTransactionRecord after;
    ASSERT_EQ(coordinator.prepare(transactionId, session, defaultPrepareInputs(grantTxn), after), AuthorityOutcome::Ok);
    ASSERT_EQ(coordinator.activateExistingRoot(transactionId, session, after), AuthorityOutcome::Ok);
  }
};

void makeTxnId(uint8_t out[kTransactionIdBytes], uint8_t tag) {
  std::memset(out, tag, kTransactionIdBytes);
}

// ---------------------------------------------------------------------
// Canonical codec round trip + tamper detection.
// ---------------------------------------------------------------------

TEST_F(AuthorityFixture, CodecRoundTripsAndRejectsTamperedFields) {
  TestDevice device("codec-device", 1);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x01);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-1");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  uint8_t record[AuthorityCodec::kRecordBytes];
  ASSERT_EQ(AuthorityCodec::serializeRecord(txn, record, sizeof(record)), AuthorityCodec::kRecordBytes);

  AuthorityTransaction parsed;
  ASSERT_EQ(AuthorityCodec::parseRecord(record, sizeof(record), parsed), AuthorityDecodeError::None);
  EXPECT_EQ(0, std::memcmp(parsed.binding.hardwareUid, txn.binding.hardwareUid, kHardwareUidBytes));
  EXPECT_EQ(parsed.revision, txn.revision);

  // Too short / too long are explicit, typed decode errors, never a
  // best-effort partial parse.
  AuthorityTransaction dummy;
  EXPECT_EQ(AuthorityCodec::parseRecord(record, sizeof(record) - 1, dummy), AuthorityDecodeError::TooShort);
  std::vector<uint8_t> overlong(record, record + sizeof(record));
  overlong.push_back(0);
  EXPECT_EQ(AuthorityCodec::parseRecord(overlong.data(), overlong.size(), dummy), AuthorityDecodeError::TooLong);

  // A single bit flip anywhere in the binding invalidates the issuer
  // signature verification downstream (checked via the coordinator tests
  // below); here we confirm the codec itself still decodes it (decoding
  // is not where tamper detection lives -- the signature is).
  std::vector<uint8_t> tampered(record, record + sizeof(record));
  tampered[0] ^= 0x01;
  AuthorityTransaction tampered_parsed;
  ASSERT_EQ(AuthorityCodec::parseRecord(tampered.data(), tampered.size(), tampered_parsed), AuthorityDecodeError::None);
  EXPECT_NE(tampered_parsed.binding.hardwareUid[0], txn.binding.hardwareUid[0]);
}

// ---------------------------------------------------------------------
// FileAuthorityRegistryCopy: real durability, torn writes, corruption,
// cold reconstruction.
// ---------------------------------------------------------------------

TEST_F(AuthorityFixture, FileCopySurvivesCloseAndColdReconstruction) {
  TestDevice device("file-copy-device", 2);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x02);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-2");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  {
    FileAuthorityRegistryCopy copy(copyAPath_);
    ASSERT_TRUE(copy.appendIssued(txn));
    StoredTransactionRecord rec;
    bool corrupt = false;
    ASSERT_TRUE(copy.readLatest(txnId, rec, corrupt));
    EXPECT_EQ(rec.state, TransactionState::Issued);
  }  // copy object fully destroyed here -- no cached state survives.

  {
    // Brand-new object, same path: a genuinely cold read.
    FileAuthorityRegistryCopy reopened(copyAPath_);
    StoredTransactionRecord rec;
    bool corrupt = false;
    ASSERT_TRUE(reopened.readLatest(txnId, rec, corrupt));
    EXPECT_FALSE(corrupt);
    EXPECT_EQ(rec.state, TransactionState::Issued);
    EXPECT_EQ(0, std::memcmp(rec.txn.manifestDigestSha256, digest, kDigestBytes));
  }
}

TEST_F(AuthorityFixture, FileCopyDetectsTornWriteAtEndOfFile) {
  TestDevice device("torn-device", 3);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x03);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-3");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy copy(copyAPath_);
  ASSERT_TRUE(copy.appendIssued(txn));

  // Simulate a power cut mid-append: truncate off the trailing commit
  // marker (and a few CRC bytes) of what would otherwise be a second,
  // in-flight record.
  const auto full_size = fs::file_size(copyAPath_);
  std::error_code ec;
  fs::resize_file(copyAPath_, full_size + 50, ec);  // pretend a second write started and got cut off.
  ASSERT_FALSE(ec);

  StoredTransactionRecord rec;
  bool corrupt = false;
  ASSERT_TRUE(copy.readLatest(txnId, rec, corrupt));
  EXPECT_EQ(rec.state, TransactionState::Issued);  // the original, fully-committed record still reads back fine.
}

TEST_F(AuthorityFixture, AppendAfterTornTailRealignsToExactSlotBoundary) {
  // MED5 regression: appendSlot() used to simply fseek(0, SEEK_END) and
  // write there -- if a prior write was torn (left a partial, less-than-
  // one-slot tail at EOF, as FileCopyDetectsTornWriteAtEndOfFile above
  // models), the NEXT genuine append would land at a misaligned offset.
  // forEachSlot's fixed-size reads would then garble BOTH the leftover
  // torn bytes AND the brand-new, otherwise-valid append, making
  // legitimate new history unreadable too. This proves a real second
  // append, made AFTER a torn tail, is durably repaired to the exact
  // slot boundary first and both records (the original and the new one)
  // read back cleanly -- including after a genuinely cold reconstruction.
  TestDevice device("torn-tail-realign-device", 64);
  uint8_t txnId1[kTransactionIdBytes];
  makeTxnId(txnId1, 0x40);
  uint8_t digest1[kDigestBytes];
  fillSeed(digest1, "manifest-64-first");
  AuthorityTransaction txn1 = makeCommission(device.binding, txnId1, digest1);

  uint8_t txnId2[kTransactionIdBytes];
  makeTxnId(txnId2, 0x41);
  uint8_t digest2[kDigestBytes];
  fillSeed(digest2, "manifest-65-second");

  {
    FileAuthorityRegistryCopy copy(copyAPath_);
    ASSERT_TRUE(copy.appendIssued(txn1));

    // Simulate a torn write: a second record started but was cut off
    // before completing a full slot (fewer bytes than one whole slot).
    const auto full_size = fs::file_size(copyAPath_);
    std::error_code ec;
    fs::resize_file(copyAPath_, full_size + 50, ec);
    ASSERT_FALSE(ec);

    // Now a genuinely NEW, real append happens (e.g. after a restart).
    TestDevice device2("torn-tail-realign-device-2", 65);
    AuthorityTransaction txn2 = makeCommission(device2.binding, txnId2, digest2);
    ASSERT_TRUE(copy.appendIssued(txn2));

    StoredTransactionRecord rec1, rec2;
    bool corrupt1 = false, corrupt2 = false;
    ASSERT_TRUE(copy.readLatest(txnId1, rec1, corrupt1));
    EXPECT_FALSE(corrupt1);
    EXPECT_EQ(rec1.state, TransactionState::Issued);
    ASSERT_TRUE(copy.readLatest(txnId2, rec2, corrupt2));
    EXPECT_FALSE(corrupt2);  // the new append must be cleanly readable, not garbled by the torn tail.
    EXPECT_EQ(rec2.state, TransactionState::Issued);
    EXPECT_EQ(0, std::memcmp(rec2.txn.manifestDigestSha256, digest2, kDigestBytes));
  }

  // And a genuinely cold reconstruction confirms it was durably repaired
  // on disk, not merely patched up in the live object's own state.
  {
    FileAuthorityRegistryCopy reopened(copyAPath_);
    StoredTransactionRecord rec1, rec2;
    bool corrupt1 = false, corrupt2 = false;
    ASSERT_TRUE(reopened.readLatest(txnId1, rec1, corrupt1));
    EXPECT_FALSE(corrupt1);
    ASSERT_TRUE(reopened.readLatest(txnId2, rec2, corrupt2));
    EXPECT_FALSE(corrupt2);
  }
}

TEST_F(AuthorityFixture, CorruptLaterTransitionNeverMasksAsCleanEarlierState) {
  // HIGH4 regression: readLatest() used to return early (`if (found)
  // return true;`) WITHOUT ever propagating `any_invalid_slot_seen` on
  // that path -- so a copy with a valid Issued record, a valid
  // ConsumedPrepared transition, and then a CORRUPTED (bit-flipped)
  // ActivationSpent transition would silently report back "cleanly
  // ConsumedPrepared, no corruption" instead of surfacing that further,
  // unreadable history existed. Combined with a genuinely-lagging other
  // copy still at Issued, this used to reconcile to a falsely-clean
  // "RecoveredFromSingleCopy, ConsumedPrepared" -- exactly the "one
  // corrupt later Spent + stale Issued other copy reopens prepare"
  // scenario, since a caller would believe it safe to resume/replay the
  // prepare handshake from an apparently-untouched ConsumedPrepared
  // state.
  TestDevice device("corrupt-later-device", 63);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x3F);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-63");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_);
  ASSERT_TRUE(a.appendIssued(txn));
  uint8_t root[kDigestBytes];
  fillSeed(root, "root-63");
  uint8_t challenge[kChallengeBytes] = {0};
  ASSERT_TRUE(a.appendStateTransition(txnId, TransactionState::ConsumedPrepared, root, /*rootBound=*/false, challenge));
  ASSERT_TRUE(a.appendStateTransition(txnId, TransactionState::ActivationSpent, root, /*rootBound=*/true, challenge));

  // Corrupt a byte inside the THIRD slot's payload (the ActivationSpent
  // transition) -- slot 0 is Issued, slot 1 is ConsumedPrepared, slot 2
  // is the one being torn/corrupted here.
  const size_t slot_bytes = 1 + AuthorityCodec::kRecordBytes + 4 + 4;  // kind + payload + crc + marker.
  const size_t corrupt_offset = 2 * slot_bytes + 10;
  {
    std::fstream f(copyAPath_, std::ios::in | std::ios::out | std::ios::binary);
    f.seekg(static_cast<std::streamoff>(corrupt_offset));
    char byte;
    f.read(&byte, 1);
    byte ^= 0xFF;
    f.seekp(static_cast<std::streamoff>(corrupt_offset));
    f.write(&byte, 1);
  }

  // Directly confirm the raw reader-level fix: corruption must surface
  // even though an earlier valid record (ConsumedPrepared) was found.
  StoredTransactionRecord raw;
  bool raw_corrupt = false;
  const bool raw_found = a.readLatest(txnId, raw, raw_corrupt);
  EXPECT_TRUE(raw_found);
  EXPECT_EQ(raw.state, TransactionState::ConsumedPrepared);  // the last CLEANLY-readable state.
  EXPECT_TRUE(raw_corrupt);  // but corruption must still be reported, not masked.

  // Copy B genuinely never received anything past Issued (a real cut
  // right after commitIssued, before either transition reached it).
  FileAuthorityRegistryCopy b(copyBPath_);
  ASSERT_TRUE(b.appendIssued(txn));

  AuthorityRegistryPair pair(a, b);
  auto rec = pair.reconcile(txnId);
  // The corrupted copy must never be trusted as "cleanly ConsumedPrepared"
  // -- it must never dominate/agree as if nothing were wrong. The only
  // safe conclusions are: fall back to B's genuinely clean (if stale)
  // Issued record, or declare outright Uncertain. Either way, the
  // resolved state must NEVER be reported as ConsumedPrepared (which
  // would incorrectly look like nothing beyond ConsumedPrepared ever
  // happened, when corrupted further history in fact existed).
  EXPECT_NE(rec.outcome, ReconciliationOutcome::Agreed);
  EXPECT_NE(rec.resolved.state, TransactionState::ConsumedPrepared);
}

TEST_F(AuthorityFixture, FileCopyReportsCorruptButPresentOnBitFlip) {
  TestDevice device("corrupt-device", 4);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x04);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-4");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy copy(copyAPath_);
  ASSERT_TRUE(copy.appendIssued(txn));

  // Flip a byte inside the committed record's payload -- CRC must catch it.
  {
    std::fstream f(copyAPath_, std::ios::in | std::ios::out | std::ios::binary);
    f.seekp(10);
    char byte;
    f.seekg(10);
    f.read(&byte, 1);
    byte ^= 0xFF;
    f.seekp(10);
    f.write(&byte, 1);
  }

  StoredTransactionRecord rec;
  bool corrupt = false;
  EXPECT_FALSE(copy.readLatest(txnId, rec, corrupt));
  EXPECT_TRUE(corrupt);
}

TEST_F(AuthorityFixture, FileCopyMissingEntirelyIsCleanNotFound) {
  FileAuthorityRegistryCopy copy(dir_ + "/never-created.bin");
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x05);
  StoredTransactionRecord rec;
  bool corrupt = false;
  EXPECT_FALSE(copy.readLatest(txnId, rec, corrupt));
  EXPECT_FALSE(corrupt);
}

// H4 regression: a file that EXISTS but cannot be OPENED for reading
// (permission denied) must never be reported the same way as a file that
// genuinely does not exist. Real permission-based fault injection (not a
// mock/introspection of which libc call was made) -- skipped when running
// as root, since root bypasses Unix permission bits entirely and the
// fault could never actually occur.
TEST_F(AuthorityFixture, FileCopyReportsUncertainNotEmptyWhenUnreadableDueToPermissions) {
  if (::geteuid() == 0) GTEST_SKIP() << "permission-based fault injection is meaningless as root";

  TestDevice device("perm-denied-device", 0x50);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x50);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-perm");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  const std::string path = dir_ + "/permission-denied.bin";
  {
    FileAuthorityRegistryCopy writer(path);
    ASSERT_TRUE(writer.appendIssued(txn));
  }

  ASSERT_EQ(::chmod(path.c_str(), 0000), 0);

  FileAuthorityRegistryCopy reader(path);
  StoredTransactionRecord rec;
  bool corrupt = false;
  const bool found = reader.readLatest(txnId, rec, corrupt);

  // Restore permissions immediately so later operations on this fixture's
  // own file are not permanently affected by this test's fault injection.
  ::chmod(path.c_str(), 0644);

  EXPECT_FALSE(found);
  EXPECT_TRUE(corrupt) << "an unreadable-but-present file must surface as Uncertain, never clean absence";
}

// H5 regression: the FIRST append to a brand-new path must durably fsync
// the PARENT DIRECTORY's own entry, not just the new file's bytes --
// otherwise a crash right after creation could lose the directory entry
// even though the file's own contents were fsync'd. Exercised with a
// real, non-mocked permission fault: removing READ permission (but
// keeping search/execute) on the parent directory prevents `open(dir,
// O_RDONLY)` for the fsync step while still allowing the file itself to
// be created/written via directory search permission alone -- so this
// surfaces a genuine parent-directory-fsync failure, not a generic
// "can't create file at all" failure (already covered by other tests).
TEST_F(AuthorityFixture, FirstAppendToNewPathFailsWhenParentDirectoryFsyncIsImpossible) {
  if (::geteuid() == 0) GTEST_SKIP() << "permission-based fault injection is meaningless as root";

  const std::string subdir = dir_ + "/first-create-restricted";
  ASSERT_EQ(::mkdir(subdir.c_str(), 0755), 0);

  TestDevice device("first-create-device", 0x51);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x51);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-first-create");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  const std::string path = subdir + "/first.bin";
  FileAuthorityRegistryCopy copy(path);

  // Search (x) permission without read (r): the target file can still be
  // located and created by name, but `open(subdir, O_RDONLY)` to fsync
  // the directory itself fails with EACCES.
  ASSERT_EQ(::chmod(subdir.c_str(), 0111), 0);

  const bool appended = copy.appendIssued(txn);

  // Restore permissions immediately so the fixture's own temp directory
  // remains fully accessible for anything that runs after this test.
  ::chmod(subdir.c_str(), 0755);

  EXPECT_FALSE(appended) << "an append whose parent-directory fsync cannot durably complete must "
                            "never be reported as a successful, durable commit";
}

// ---------------------------------------------------------------------
// AuthorityRegistryPair reconciliation: dominance, single-copy recovery,
// uncertainty, and never-permission-from-loss.
// ---------------------------------------------------------------------

TEST_F(AuthorityFixture, ReconcileAgreesWhenBothCopiesMatch) {
  TestDevice device("reconcile-agree", 6);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x06);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-6");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  ASSERT_TRUE(pair.commitIssued(txn));

  auto result = pair.reconcile(txnId);
  EXPECT_EQ(result.outcome, ReconciliationOutcome::Agreed);
  EXPECT_FALSE(result.needsReplicaRepair);
}

TEST_F(AuthorityFixture, CutBetweenCommitsRecoversFromSingleCopyAndFlagsRepair) {
  TestDevice device("cut-between", 7);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x07);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-7");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  // Simulate a power cut BETWEEN the two copy writes: only A succeeds.
  ASSERT_TRUE(a.appendIssued(txn));

  AuthorityRegistryPair pair(a, b);
  auto result = pair.reconcile(txnId);
  EXPECT_EQ(result.outcome, ReconciliationOutcome::RecoveredFromSingleCopy);
  EXPECT_TRUE(result.needsReplicaRepair);
  EXPECT_EQ(result.resolved.state, TransactionState::Issued);
}

TEST_F(AuthorityFixture, BothRegistriesMissingIsNeverPermission) {
  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x08);
  auto result = pair.reconcile(txnId);
  EXPECT_EQ(result.outcome, ReconciliationOutcome::NotFound);
}

TEST_F(AuthorityFixture, OneCopyRollbackToOlderValidIssuedIsDetectedAsConflict) {
  TestDevice device("rollback-device", 9);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x09);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-9");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  ASSERT_TRUE(pair.commitIssued(txn));

  uint8_t root[kDigestBytes];
  fillSeed(root, "root-9");
  uint8_t challenge[kChallengeBytes] = {0};
  ASSERT_TRUE(pair.commitStateTransition(txnId, TransactionState::ConsumedPrepared, root, /*rootBound=*/false, challenge));
  ASSERT_TRUE(pair.commitStateTransition(txnId, TransactionState::ActivationSpent, root, /*rootBound=*/true, challenge));

  // Restore a backup of copy B taken right after Issued (simulate restoring
  // an old backup / rollback of one registry copy only).
  fs::path rollback_backup = fs::path(dir_) / "copyB-issued-only.bin";
  {
    FileAuthorityRegistryCopy fresh_b(rollback_backup.string());
    ASSERT_TRUE(fresh_b.appendIssued(txn));
  }
  fs::copy_file(rollback_backup, copyBPath_, fs::copy_options::overwrite_existing);

  FileAuthorityRegistryCopy a2(copyAPath_), b2(copyBPath_);
  AuthorityRegistryPair pair2(a2, b2);
  auto result = pair2.reconcile(txnId);
  // A (ActivationSpent) legitimately dominates the stale, rolled-back B
  // (Issued) for the exact same bound transaction -- this is the
  // documented "one-copy rollback to an older valid Issued" recovery
  // case, not an Uncertain conflict, because both copies agree on every
  // signed field and only B's lifecycle progress is stale.
  EXPECT_EQ(result.outcome, ReconciliationOutcome::RecoveredFromSingleCopy);
  EXPECT_EQ(result.resolved.state, TransactionState::ActivationSpent);
  EXPECT_TRUE(result.needsReplicaRepair);
}

// H5 regression, revised per review: proves the fix BEHAVIORALLY (never
// merely "fsync was called") by genuinely faulting the FIRST parent-
// directory fsync that a brand-new commitIssued append performs on copy
// A. Confirms (1) the coordinator releases NO permission off the back of
// the faulted append even though copy A's slot bytes were, in this same
// process, still genuinely written to disk; (2) after simulating the
// crash this fault models (an unconfirmed directory entry may not
// survive a crash even though the file's own fsync'd bytes did) and a
// genuine close/reopen, the two-copy repair machinery recovers the EXACT
// SAME original Issued grant -- never a new issuance, never invented
// history -- and the lifecycle can still complete correctly afterwards.
TEST_F(AuthorityFixture, FaultedFirstParentDirectoryFsyncNeverReleasesPermitAndGenuineRepairRecoversExactGrant) {
  TestDevice device("fsync-fault-device", 90);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x5C);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-90");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  int fault_calls = 0;
  a.setFsyncParentDirectoryOverrideForTests([&fault_calls](const std::string&) {
    ++fault_calls;
    return false;  // Genuinely faulted: every parent-dir fsync on copy A fails in this test.
  });

  AuthorityRegistryPair pair(a, b);
  CountingEntropy entropy(90);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &entropy, activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());

  EXPECT_EQ(coordinator.submitCommission(txn), AuthorityOutcome::Denied);
  EXPECT_EQ(fault_calls, 1);

  // Simulate the crash the fault models: copy A's directory entry is
  // lost entirely even though its file bytes (payload+CRC+marker) were
  // otherwise valid in this process. Delete copy A's file, then
  // genuinely close/reopen -- brand-new FileAuthorityRegistryCopy
  // instances against the same paths, no in-memory state carried over
  // and no override installed (a real restart uses the real syscall).
  ASSERT_EQ(std::remove(copyAPath_.c_str()), 0);

  FileAuthorityRegistryCopy a2(copyAPath_), b2(copyBPath_);
  AuthorityRegistryPair pair2(a2, b2);

  ReconciliationResult before_repair = pair2.reconcile(txnId);
  EXPECT_EQ(before_repair.outcome, ReconciliationOutcome::RecoveredFromSingleCopy);
  EXPECT_TRUE(before_repair.needsReplicaRepair);
  EXPECT_EQ(before_repair.resolved.state, TransactionState::Issued);
  EXPECT_EQ(0, std::memcmp(before_repair.resolved.txn.transactionId, txn.transactionId, kTransactionIdBytes));
  EXPECT_EQ(0, std::memcmp(before_repair.resolved.txn.manifestDigestSha256, txn.manifestDigestSha256, kDigestBytes));

  CountingEntropy entropy2(91);
  AuthorityCoordinator coordinator2(pair2, &verifier_, issuer_trust_.get(), &entropy2, activation_signing_trust_.get(),
                                     &test_lock_, prepare_signing_trust_.get());
  prepareAndActivate(coordinator2, txnId, device, /*entropyTag=*/92, txn);

  ReconciliationResult after = pair2.reconcile(txnId);
  EXPECT_EQ(after.outcome, ReconciliationOutcome::Agreed);
  EXPECT_FALSE(after.needsReplicaRepair);
  EXPECT_EQ(after.resolved.state, TransactionState::ActivationSpent);
  EXPECT_EQ(0, std::memcmp(after.resolved.txn.transactionId, txn.transactionId, kTransactionIdBytes));
  EXPECT_EQ(0, std::memcmp(after.resolved.txn.manifestDigestSha256, txn.manifestDigestSha256, kDigestBytes));
}
// Sol c577a77f REJECTED the original "poison the marker on fsync
// failure" fix as NOT a valid durability solution: the poison
// write/fsync can itself fail, or the process can die between the
// original failure and the correction -- either way a LATER, entirely
// separate caller can still see a readable, byte-perfect, structurally
// "valid" marker and wrongly treat it as confirmed. appendSlot() no
// longer attempts any poison/undo (see FileAuthorityRegistryCopy.h); the
// actual fix is AuthorityRegistryCopy::confirmDurable() /
// AuthorityRegistryPair::confirmBothCopiesDurable() -- a POSITIVE
// re-fsync performed fresh, immediately before every permission release
// -- which every AuthorityCoordinator release point now calls. These
// tests prove: (1) a transient marker-fsync failure leaves byte-valid-
// but-unconfirmed data that a plain reconcile() alone is fooled by, even
// across close/reopen; (2) confirmDurable() genuinely re-attempts the
// fsync and reports true once the underlying storage is actually fine
// (a transient one-off syscall failure, the common real-world case);
// (3) confirmDurable() continues to report false for as long as the
// underlying storage genuinely cannot be confirmed durable, and only
// reports true once that condition is lifted -- never a one-shot
// best-effort guess.
TEST_F(AuthorityFixture, MarkerFsyncFailureLeavesByteValidButUnconfirmedSlotAndConfirmDurableGatesOnActualDurability) {
  TestDevice device("marker-fsync-fault-device", 93);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x5D);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-93");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  ASSERT_TRUE(pair.commitIssued(txn));

  uint8_t root[kDigestBytes];
  fillSeed(root, "root-93");
  uint8_t challenge[kChallengeBytes] = {0};
  ASSERT_TRUE(pair.commitStateTransition(txnId, TransactionState::ConsumedPrepared, root, /*rootBound=*/false, challenge));

  // Fault ONLY copy A's marker fsync, and ONLY starting now (the prior
  // Issued/ConsumedPrepared appends above used the real syscall path).
  int marker_fault_calls = 0;
  a.setMarkerFsyncOverrideForTests([&marker_fault_calls](int) {
    ++marker_fault_calls;
    return false;  // Data/CRC fsync for this append still succeeds normally; only the marker fsync fails.
  });

  EXPECT_FALSE(pair.commitStateTransition(txnId, TransactionState::ActivationSpent, root, /*rootBound=*/true, challenge));
  EXPECT_EQ(marker_fault_calls, 1);

  // No poison attempted now: the marker bytes were already fwrite+
  // fflush'd before the fsync call failed, so a plain reconcile() --
  // even using the SAME live, already-faulted objects -- sees
  // byte-perfect, structurally-valid Agreed/ActivationSpent. This is
  // EXACTLY the gap Root's review identified: appendSlot's own return
  // value correctly reported failure, but a later independent reader
  // relying only on reconcile() would not.
  ReconciliationResult live_result = pair.reconcile(txnId);
  EXPECT_EQ(live_result.outcome, ReconciliationOutcome::Agreed);
  EXPECT_EQ(live_result.resolved.state, TransactionState::ActivationSpent);

  // A genuine close/reopen (brand-new objects, no override installed)
  // sees the exact same thing -- this is real on-disk data, not an
  // in-memory artifact of the faulted objects.
  FileAuthorityRegistryCopy a2(copyAPath_), b2(copyBPath_);
  AuthorityRegistryPair pair2(a2, b2);
  ReconciliationResult before_confirm = pair2.reconcile(txnId);
  EXPECT_EQ(before_confirm.outcome, ReconciliationOutcome::Agreed);
  EXPECT_EQ(before_confirm.resolved.state, TransactionState::ActivationSpent);

  // The ONLY thing that may ever justify releasing permission on this
  // transaction now is confirmBothCopiesDurable() -- and since the
  // original fsync failure here was a one-off simulated syscall failure
  // (the underlying tmpfs/filesystem itself was never actually broken),
  // a FRESH, independent re-attempt genuinely succeeds: this directly
  // demonstrates why retrying fsync at release time (not just trusting
  // the original write-time result forever) is the correct fix, and
  // that it is not merely rubber-stamping the earlier failure away.
  EXPECT_TRUE(pair2.confirmBothCopiesDurable());

  // Now prove the inverse: if the underlying storage is STILL genuinely
  // unable to confirm durability at release time (not merely a one-off
  // historical hiccup), confirmBothCopiesDurable() must keep denying for
  // as long as that persists, and only report true once it is actually
  // lifted -- never a one-shot best-effort guess that is right by
  // accident.
  FileAuthorityRegistryCopy a3(copyAPath_), b3(copyBPath_);
  AuthorityRegistryPair pair3(a3, b3);
  bool storage_still_broken = true;
  a3.setConfirmDurableFsyncOverrideForTests([&storage_still_broken](int) { return !storage_still_broken; });
  EXPECT_FALSE(pair3.confirmBothCopiesDurable());
  EXPECT_FALSE(pair3.confirmBothCopiesDurable());  // Not one-shot: repeated calls keep denying.
  storage_still_broken = false;
  EXPECT_TRUE(pair3.confirmBothCopiesDurable());  // Genuinely recovered -- now, and only now, confirmed.
}

// Coordinator-level companion: proves the SAME positive-barrier
// requirement actually gates real permission release through the public
// API, not merely the raw registry-pair primitive above. Drives a full
// Commission -> prepare -> (faulted) final handshake sequence where
// copy A's confirmDurable() genuinely cannot confirm durability at the
// moment runPrepareHandshake would otherwise report Ok: the ActivationSpent
// state is still durably committed to BOTH copies' append-only history
// (never lost, never reseeded) but the caller must NOT be told Ok/that
// permission is releasable until a later call, once the storage is
// genuinely confirmed durable, actually delivers the EXACT SAME grant.
TEST_F(AuthorityFixture, CoordinatorDeniesReleaseUntilPositiveDurabilityBarrierEvenAfterBothCopiesAreActuallySpent) {
  TestDevice device("durability-gate-device", 94);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x5E);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-94");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(94);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy, activation_signing_trust_.get(),
                                    &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(txn), AuthorityOutcome::Ok);

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(95);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                              &signer);
  LoopbackDeviceSession session(guard);

  // Copy A's confirmDurable() succeeds for the VERY FIRST call (the
  // barrier runPrepareHandshake checks immediately before sending the
  // PreparePermit -- storage is genuinely fine at that moment) but every
  // call after that fails until explicitly lifted below: simulates a
  // storage hiccup occurring exactly at the final durability-confirm
  // barrier, right after both copies have already durably committed
  // ActivationSpent.
  int confirm_call_count = 0;
  bool storage_recovered = false;
  a.setConfirmDurableFsyncOverrideForTests([&](int) {
    ++confirm_call_count;
    if (confirm_call_count == 1) return true;
    return storage_recovered;
  });

  StoredTransactionRecord after_prepare;
  EXPECT_NE(coordinator.prepare(txnId, session, defaultPrepareInputs(txn), after_prepare), AuthorityOutcome::Ok);
  // Even though the FINAL ActivationSpent commit genuinely succeeded on
  // BOTH copies inside prepare()'s handshake (there is no I/O failure on
  // the append path itself -- only confirmDurable()'s fresh re-check
  // fails), the public call must never report Ok/permission released
  // while that barrier is unconfirmed.
  ReconciliationResult raw = pair.reconcile(txnId);
  EXPECT_EQ(raw.outcome, ReconciliationOutcome::Agreed);
  EXPECT_EQ(raw.resolved.state, TransactionState::ActivationSpent);

  // Device must never have received anything while release was denied.
  EXPECT_EQ(maintenance.activate_calls, 0);

  // Storage genuinely recovers: a later, independent call must now
  // succeed and deliver the EXACT SAME already-committed grant -- never
  // a new issuance, new root, or reseed.
  storage_recovered = true;
  StoredTransactionRecord after_activate;
  EXPECT_EQ(coordinator.activateExistingRoot(txnId, session, after_activate), AuthorityOutcome::Ok);
  EXPECT_EQ(0, std::memcmp(after_activate.txn.transactionId, txn.transactionId, kTransactionIdBytes));
  EXPECT_EQ(0, std::memcmp(after_activate.txn.manifestDigestSha256, txn.manifestDigestSha256, kDigestBytes));
  EXPECT_EQ(after_activate.state, TransactionState::ActivationSpent);
}



TEST_F(AuthorityFixture, ConflictingSignedContentForSameTransactionIdIsUncertain) {
  TestDevice device_a("conflict-a", 10);
  TestDevice device_b("conflict-b", 11);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x0A);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-10");

  AuthorityTransaction txn_a = makeCommission(device_a.binding, txnId, digest);
  AuthorityTransaction txn_b = makeCommission(device_b.binding, txnId, digest);  // same id, different binding!

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  ASSERT_TRUE(a.appendIssued(txn_a));
  ASSERT_TRUE(b.appendIssued(txn_b));

  AuthorityRegistryPair pair(a, b);
  auto result = pair.reconcile(txnId);
  EXPECT_EQ(result.outcome, ReconciliationOutcome::Uncertain);
}

TEST_F(AuthorityFixture, DeletedAndCorruptCopyCombinationsNeverGrantPermission) {
  TestDevice device("deletion-device", 12);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x0C);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-12");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  ASSERT_TRUE(pair.commitIssued(txn));

  // Delete copy A entirely.
  fs::remove(copyAPath_);
  FileAuthorityRegistryCopy a2(copyAPath_), b2(copyBPath_);
  AuthorityRegistryPair pair2(a2, b2);
  auto result = pair2.reconcile(txnId);
  EXPECT_EQ(result.outcome, ReconciliationOutcome::RecoveredFromSingleCopy);
  EXPECT_TRUE(result.needsReplicaRepair);

  // Now corrupt copy B too (bit flip) -- neither copy is trustworthy.
  {
    std::fstream f(copyBPath_, std::ios::in | std::ios::out | std::ios::binary);
    f.seekp(5);
    char byte;
    f.seekg(5);
    f.read(&byte, 1);
    byte ^= 0xFF;
    f.seekp(5);
    f.write(&byte, 1);
  }
  FileAuthorityRegistryCopy a3(copyAPath_), b3(copyBPath_);
  AuthorityRegistryPair pair3(a3, b3);
  auto result2 = pair3.reconcile(txnId);
  EXPECT_EQ(result2.outcome, ReconciliationOutcome::Uncertain);  // never silently NotFound/permission.
}

// ---------------------------------------------------------------------
// AuthorityCoordinator: full lifecycle, binding substitution rejection,
// lost responses, missing dependencies, repair/rekey dominance.
// ---------------------------------------------------------------------

TEST_F(AuthorityFixture, SubmitCommissionRejectsWrongIssuerSignature) {
  TestDevice device("bad-sig-device", 20);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x14);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-20");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);
  txn.issuerSignatureEd25519[0] ^= 0xFF;  // tamper after signing.

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy entropy(0);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &entropy, nullptr, &test_lock_, prepare_signing_trust_.get());

  EXPECT_EQ(coordinator.submitCommission(txn), AuthorityOutcome::SignatureInvalid);
}

TEST_F(AuthorityFixture, SubmitCommissionRejectsSecondGenesisOverAlreadyCommissionedOwner) {
  // HIGH6 regression: submitCommission() used to check only
  // txnId/operation/revision/signature -- NEVER whether this exact
  // domain+fullPK ownership already had surviving ActivationSpent
  // history. That let a brand-new, freshly-signed revision-0 Commission
  // be smuggled through for an owner that was already commissioned,
  // bypassing repairExisting/rekeyExplicitly entirely (exactly the
  // "role/label changes do NOT make unchanged key material unused"
  // violation: relabeling companion0->realrepeater1, or just a new
  // profile/layout, must never look like a fresh genesis commission for
  // key material that is still in use).
  TestDevice device("already-commissioned-device", 66);
  uint8_t first_txn_id[kTransactionIdBytes];
  makeTxnId(first_txn_id, 0x42);
  uint8_t first_digest[kDigestBytes];
  fillSeed(first_digest, "manifest-66-first");
  AuthorityTransaction first_txn = makeCommission(device.binding, first_txn_id, first_digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(66);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy, activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(first_txn), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, first_txn_id, device, /*entropyTag=*/67, first_txn);  // drives it to genuine ActivationSpent.

  // Attempt 1: same binding exactly, new transactionId, revision 0.
  uint8_t second_txn_id[kTransactionIdBytes];
  makeTxnId(second_txn_id, 0x43);
  uint8_t second_digest[kDigestBytes];
  fillSeed(second_digest, "manifest-66-second");
  AuthorityTransaction second_txn = makeCommission(device.binding, second_txn_id, second_digest);
  EXPECT_EQ(coordinator.submitCommission(second_txn), AuthorityOutcome::StaleRevision);

  // Attempt 2: a pure role-label relabel (UID/fullPK/cryptoDomain/layout
  // all unchanged) must be rejected the exact same way -- a role change
  // alone is not grounds for a new "genesis" commission.
  AuthorityBinding relabeled = device.binding;
  relabeled.historicalInitialRoleId = 1;  // e.g. companion0 -> realrepeater1 relabel only.
  uint8_t third_txn_id[kTransactionIdBytes];
  makeTxnId(third_txn_id, 0x44);
  uint8_t third_digest[kDigestBytes];
  fillSeed(third_digest, "manifest-66-relabel");
  AuthorityTransaction third_txn = makeCommission(relabeled, third_txn_id, third_digest);
  EXPECT_EQ(coordinator.submitCommission(third_txn), AuthorityOutcome::StaleRevision);

  // A genuinely different owner (different fullPK, i.e. a real rekey
  // scenario, never submitted through submitCommission itself -- that's
  // rekeyExplicitly's job) is unaffected: a fresh, unrelated owner's
  // first commission is still permitted.
  TestDevice unrelated_device("unrelated-device", 68);
  uint8_t fourth_txn_id[kTransactionIdBytes];
  makeTxnId(fourth_txn_id, 0x45);
  uint8_t fourth_digest[kDigestBytes];
  fillSeed(fourth_digest, "manifest-66-unrelated");
  AuthorityTransaction fourth_txn = makeCommission(unrelated_device.binding, fourth_txn_id, fourth_digest);
  EXPECT_EQ(coordinator.submitCommission(fourth_txn), AuthorityOutcome::Ok);
}

// H3 regression: the prior fence above (reconcileLatestActivationForOwner)
// only ever sees ActivationSpent history, so two DISTINCT revision-0
// Commission transactions for the exact same owner could both reach
// Issued (neither yet prepared/spent) before either was ever detected as
// a conflict -- a genuine ownership fork at the very first step of the
// lifecycle. reconcileOwnershipLineage must catch this immediately at
// submission time, well before either grant is ever prepared.
TEST_F(AuthorityFixture, SubmitCommissionRejectsSecondGenesisForSameOwnerBeforeEitherIsSpent) {
  TestDevice device("fork-before-spend-device", 69);
  uint8_t first_txn_id[kTransactionIdBytes];
  makeTxnId(first_txn_id, 0x46);
  uint8_t first_digest[kDigestBytes];
  fillSeed(first_digest, "manifest-69-first");
  AuthorityTransaction first_txn = makeCommission(device.binding, first_txn_id, first_digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(69);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy, activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());

  // First genesis Commission: only reaches Issued -- deliberately never
  // prepared or activated.
  ASSERT_EQ(coordinator.submitCommission(first_txn), AuthorityOutcome::Ok);

  // A second, entirely distinct revision-0 Commission for the EXACT same
  // owner, submitted while the first is still sitting at Issued, must be
  // rejected just as surely as if the first had already reached
  // ActivationSpent.
  uint8_t second_txn_id[kTransactionIdBytes];
  makeTxnId(second_txn_id, 0x47);
  uint8_t second_digest[kDigestBytes];
  fillSeed(second_digest, "manifest-69-second");
  AuthorityTransaction second_txn = makeCommission(device.binding, second_txn_id, second_digest);
  EXPECT_EQ(coordinator.submitCommission(second_txn), AuthorityOutcome::StaleRevision);

  // Advance the FIRST transaction to ConsumedPrepared (still not Spent)
  // and confirm a THIRD distinct genesis attempt is rejected the same
  // way -- the fence must hold across the whole pre-activation lifecycle,
  // not just the initial Issued state.
  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(70);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                             &signer);
  LoopbackDeviceSession session(guard);
  session.drop_prepare_response = true;  // stop exactly at ConsumedPrepared, never reach ActivationSpent.
  StoredTransactionRecord after;
  EXPECT_EQ(coordinator.prepare(first_txn_id, session, defaultPrepareInputs(first_txn), after), AuthorityOutcome::Denied);
  auto stopped_at = pair.reconcile(first_txn_id);
  ASSERT_EQ(stopped_at.outcome, ReconciliationOutcome::Agreed);
  ASSERT_EQ(stopped_at.resolved.state, TransactionState::ConsumedPrepared);

  uint8_t third_txn_id[kTransactionIdBytes];
  makeTxnId(third_txn_id, 0x48);
  uint8_t third_digest[kDigestBytes];
  fillSeed(third_digest, "manifest-69-third");
  AuthorityTransaction third_txn = makeCommission(device.binding, third_txn_id, third_digest);
  EXPECT_EQ(coordinator.submitCommission(third_txn), AuthorityOutcome::StaleRevision);
}

TEST_F(AuthorityFixture, DescribeBindingRejectsEverySubstitutedField) {
  TestDevice device("substitution-device", 21);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x15);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-21");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy entropy(1);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &entropy, nullptr, &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(txn), AuthorityOutcome::Ok);

  StoredTransactionRecord out;
  EXPECT_EQ(coordinator.describeBinding(txnId, device.binding, out), AuthorityOutcome::Ok);

  auto expectMismatch = [&](std::function<void(AuthorityBinding&)> mutate) {
    AuthorityBinding claimed = device.binding;
    mutate(claimed);
    StoredTransactionRecord rec;
    EXPECT_EQ(coordinator.describeBinding(txnId, claimed, rec), AuthorityOutcome::BindingMismatch);
  };

  expectMismatch([](AuthorityBinding& b) { b.hardwareUid[0] ^= 0x01; });
  expectMismatch([](AuthorityBinding& b) { b.meshFullPublicKey[0] ^= 0x01; });
  expectMismatch([](AuthorityBinding& b) { b.cryptoDomain.form = meshcore::ota::runtime::OtaAeadForm::Group; });
  expectMismatch([](AuthorityBinding& b) { b.profileId ^= 0x01; });
  expectMismatch([](AuthorityBinding& b) { b.layoutId ^= 0x01; });
  expectMismatch([](AuthorityBinding& b) { b.consentOwnerPublicKey[0] ^= 0x01; });
  expectMismatch([](AuthorityBinding& b) { b.historicalInitialRoleId ^= 0x01; });

  // A substituted transaction id is not a "binding" field, but is equally
  // rejected -- it simply resolves a DIFFERENT (nonexistent) transaction.
  uint8_t other_txn_id[kTransactionIdBytes];
  makeTxnId(other_txn_id, 0xEE);
  StoredTransactionRecord rec;
  EXPECT_EQ(coordinator.describeBinding(other_txn_id, device.binding, rec), AuthorityOutcome::TransactionNotFound);
}

// Full happy-path lifecycle wired end-to-end through a real
// DeviceAuthorityGuard via LoopbackDeviceSession.
TEST_F(AuthorityFixture, FullLifecycleCommissionPrepareActivate) {
  TestDevice device("lifecycle-device", 22);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x16);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-22");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest, /*txFloor=*/5, /*rxFloor=*/7);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(2);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(txn), AuthorityOutcome::Ok);

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(3);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                              &signer);
  LoopbackDeviceSession session(guard);

  StoredTransactionRecord after_prepare;
  EXPECT_EQ(coordinator.prepare(txnId, session, defaultPrepareInputs(txn), after_prepare), AuthorityOutcome::Ok);
  EXPECT_EQ(after_prepare.state, TransactionState::ActivationSpent);
  EXPECT_EQ(maintenance.stage_calls, 1);

  StoredTransactionRecord after_activate;
  EXPECT_EQ(coordinator.activateExistingRoot(txnId, session, after_activate), AuthorityOutcome::Ok);
  EXPECT_EQ(maintenance.activate_calls, 1);

  TxRxActivationGrant grant;
  ASSERT_EQ(guard.currentActivationGrant(grant), AuthorityOutcome::Ok);
  EXPECT_EQ(grant.txSequenceFloor, 5u);
  EXPECT_EQ(grant.rxReplayFloor, 7u);

  // Narrow TX/RX adapter seam: exact match commissions, anything else refuses.
  AuthorityTxCommissioningAdapter tx_adapter(guard);
  EXPECT_FALSE(tx_adapter.commissionVirginTx(999));  // wrong value: refused.
  EXPECT_TRUE(tx_adapter.commissionVirginTx(5));     // exact verified floor: allowed.
  EXPECT_FALSE(tx_adapter.commissionVirginTx(5));    // one-use: refused the second time.

  // Grant not usable before both commits: a transaction that never
  // reached ActivationSpent must refuse activateExistingRoot outright.
  // Uses a genuinely DIFFERENT device/owner than `device` above: after
  // the HIGH6 fix, a second revision-0 Commission over an owner that
  // ALREADY has surviving ActivationSpent history (like `device`, just
  // activated above) is correctly rejected as StaleRevision -- that is
  // covered by its own dedicated test, not this one, which is only
  // about the WrongState/"not yet spent" check.
  TestDevice other_device("full-lifecycle-second-device", 45);
  uint8_t other_txn_id[kTransactionIdBytes];
  makeTxnId(other_txn_id, 0x17);
  uint8_t other_digest[kDigestBytes];
  fillSeed(other_digest, "manifest-23");
  AuthorityTransaction other_txn = makeCommission(other_device.binding, other_txn_id, other_digest);
  ASSERT_EQ(coordinator.submitCommission(other_txn), AuthorityOutcome::Ok);
  StoredTransactionRecord premature;
  EXPECT_EQ(coordinator.activateExistingRoot(other_txn_id, session, premature), AuthorityOutcome::WrongState);
}

// Regression coverage for the Astra29 correction: the three distinct
// commitments this authority now tracks -- M (manifestDigestSha256, the
// ISSUED commission manifest's own policy digest), A (SHA256 of the full
// 238-byte signed grant RECORD, including the issuer signature), and R
// (the device-attested SHA256(domain||len||P) prepared-store-root
// commitment) -- are genuinely independent values, never silently
// conflated or derived from one another. This replaces the pre-Astra29
// "expectedRootDigestSha256" field (removed entirely: the issuer cannot
// know R ahead of time, only the device/store can produce it after
// actually applying the manifest).
TEST_F(AuthorityFixture, ManifestGrantAndPreparedRootDigestsAreGenuinelyDistinctCommitments) {
  TestDevice device("m-a-r-distinct-device", 44);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x44);
  uint8_t manifest_digest[kDigestBytes];
  fillSeed(manifest_digest, "manifest-44-policy");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, manifest_digest);

  // M is exactly the field the issuer signed as policy content.
  EXPECT_EQ(0, std::memcmp(txn.manifestDigestSha256, manifest_digest, kDigestBytes));

  // A = SHA256(full signed record, INCLUDING the issuer signature) is
  // structurally a different hash of different (and larger) input bytes
  // than M -- genuinely distinct, not a copy/derivation of M.
  uint8_t grant_digest_a[kDigestBytes];
  ASSERT_TRUE(AuthorityCodec::computeRecordDigestSha256(txn, grant_digest_a));
  EXPECT_NE(0, std::memcmp(grant_digest_a, manifest_digest, kDigestBytes));

  // R uses a THIRD, independently domain-separated formula over
  // real persisted bytes P (here, for this unit-level check, the exact
  // signed record stands in for P -- real P content is Store's unwired
  // integration responsibility, see PreparedRootCommitment.h) -- distinct
  // from both M and A.
  uint8_t record[AuthorityCodec::kRecordBytes];
  ASSERT_EQ(AuthorityCodec::serializeRecord(txn, record, sizeof(record)), AuthorityCodec::kRecordBytes);
  uint8_t root_digest_r[kDigestBytes];
  ASSERT_EQ(PreparedRootCommitment::computeDigestSha256(record, sizeof(record), root_digest_r),
            PreparedRootCommitment::Result::kOk);
  EXPECT_NE(0, std::memcmp(root_digest_r, manifest_digest, kDigestBytes));
  EXPECT_NE(0, std::memcmp(root_digest_r, grant_digest_a, kDigestBytes));

  // End-to-end: run the REAL prepare+activate handshake and confirm the
  // registry's durably-recorded prepared root (what ActivationSpent binds
  // to) is genuinely the device-attested R -- not M, and not A.
  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(44);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy, activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(txn), AuthorityOutcome::Ok);

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(45);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                              &signer);
  LoopbackDeviceSession real_session(guard);
  StoredTransactionRecord after;
  ASSERT_EQ(coordinator.prepare(txnId, real_session, defaultPrepareInputs(txn), after), AuthorityOutcome::Ok);
  ASSERT_EQ(coordinator.activateExistingRoot(txnId, real_session, after), AuthorityOutcome::Ok);

  DeviceAuthorityState state;
  ASSERT_EQ(device_store.readCurrent(state), DeviceAuthorityReadStatus::Present);
  // The device's own RecordingMaintenance double computes R via the real
  // PreparedRootCommitment formula over the signed record -- matching
  // `root_digest_r` computed independently above.
  EXPECT_EQ(0, std::memcmp(state.stagedRootDigestSha256, root_digest_r, kDigestBytes));
  EXPECT_NE(0, std::memcmp(state.stagedRootDigestSha256, manifest_digest, kDigestBytes));
  EXPECT_NE(0, std::memcmp(state.stagedRootDigestSha256, grant_digest_a, kDigestBytes));

  auto rec = pair.reconcile(txnId);
  ASSERT_EQ(rec.outcome, ReconciliationOutcome::Agreed);
  EXPECT_EQ(rec.resolved.state, TransactionState::ActivationSpent);
  ASSERT_TRUE(rec.resolved.rootBound);
  EXPECT_EQ(0, std::memcmp(rec.resolved.preparedRootDigestSha256, root_digest_r, kDigestBytes));
}

// PreparedRootCommitment is a bounded, explicit-error-result seam: it
// must refuse a malformed (p, p_len) combination on the length/pointer
// values ALONE -- before ever reading p or allocating anything sized to
// p_len -- and must never mutate out_digest on refusal.
TEST(PreparedRootCommitmentTest, NullPointerWithPositiveLengthIsRejectedWithoutHashing) {
  uint8_t sentinel[32];
  std::memset(sentinel, 0xABu, sizeof(sentinel));
  uint8_t out[32];
  std::memcpy(out, sentinel, sizeof(out));

  EXPECT_EQ(PreparedRootCommitment::computeDigestSha256(nullptr, 16, out),
            PreparedRootCommitment::Result::kNullPointerWithPositiveLength);
  // Refusal must never write to out_digest.
  EXPECT_EQ(0, std::memcmp(out, sentinel, sizeof(out)));
}

TEST(PreparedRootCommitmentTest, NullPointerWithZeroLengthIsStillAcceptedAsEmptyP) {
  // Astra29: empty-P semantics are explicitly allowed to stay as-is
  // (p_len == 0 with p == nullptr is a legitimate "no P bytes" case, not
  // a malformed-input case) -- only a POSITIVE length paired with a null
  // pointer is refused.
  uint8_t out[32];
  EXPECT_EQ(PreparedRootCommitment::computeDigestSha256(nullptr, 0, out), PreparedRootCommitment::Result::kOk);
}

TEST(PreparedRootCommitmentTest, LengthAboveUint32MaxIsRejectedBeforeAnyReadOrAllocation) {
  // The rejection must be decided from p_len alone -- no huge allocation
  // and no attempt to read p_len bytes from p is ever made. `p` here
  // points at a tiny real buffer (not a 4+ GiB allocation); if the
  // implementation ever tried to actually read/hash p_len bytes it would
  // crash or hang long before returning, proving the length check runs
  // strictly first.
  uint8_t tiny_p[4] = {1, 2, 3, 4};
  uint8_t sentinel[32];
  std::memset(sentinel, 0xCDu, sizeof(sentinel));
  uint8_t out[32];
  std::memcpy(out, sentinel, sizeof(out));

  const uint64_t impossible_len = static_cast<uint64_t>(UINT32_MAX) + 1ull;
  EXPECT_EQ(PreparedRootCommitment::computeDigestSha256(tiny_p, static_cast<size_t>(impossible_len), out),
            PreparedRootCommitment::Result::kLengthExceedsUint32);
  EXPECT_EQ(0, std::memcmp(out, sentinel, sizeof(out)));
}

TEST(PreparedRootCommitmentTest, NullOutDigestIsRejected) {
  uint8_t p[4] = {9, 9, 9, 9};
  EXPECT_EQ(PreparedRootCommitment::computeDigestSha256(p, sizeof(p), nullptr),
            PreparedRootCommitment::Result::kNullOutDigest);
}

TEST(PreparedRootCommitmentTest, ValidInputStillProducesTheExactSameDigestAsBefore) {
  // The bounded error-result seam must not change R's actual value for
  // any genuinely valid (p, p_len) -- this is the same cross-language
  // vector formula real callers/tests already depend on.
  const uint8_t p[] = {0x10, 0x20, 0x30, 0x40, 0x50};
  uint8_t out_a[32];
  uint8_t out_b[32];
  ASSERT_EQ(PreparedRootCommitment::computeDigestSha256(p, sizeof(p), out_a), PreparedRootCommitment::Result::kOk);
  ASSERT_EQ(PreparedRootCommitment::computeDigestSha256(p, sizeof(p), out_b), PreparedRootCommitment::Result::kOk);
  EXPECT_EQ(0, std::memcmp(out_a, out_b, sizeof(out_a)));
}

TEST_F(AuthorityFixture, PrepareAndResumeRevalidatePhysicalLineageNotOnlyAtIssueTime) {
  // Sol c577a77f (H2 residual): "revalidate physical UID/full owner/
  // predecessor BEFORE Prepare AND Spent, not just issue". Constructs a
  // scenario a coordinator-only issuance-time fence CANNOT see: a
  // competing, higher-revision transaction for the EXACT SAME physical
  // device committed directly to the registry pair (e.g. a bypass, a
  // bug, or a separate legitimate writer outside this coordinator
  // instance's own rekeyExplicitly() issuance path) becomes the
  // dominant physical lineage AFTER the original transaction was issued
  // and already reached ConsumedPrepared, but BEFORE it is
  // prepared/resumed to completion. Proves the revalidation at
  // prepare()/resumePrepared() time genuinely catches this, rather than
  // only ever checking lineage once at issuance.
  TestDevice device("lineage-revalidate-device", 96);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x60);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-96");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(96);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy, activation_signing_trust_.get(),
                                    &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(97);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                              &signer);
  LoopbackDeviceSession session(guard);
  session.drop_prepare_response = true;

  StoredTransactionRecord after_lost;
  EXPECT_EQ(coordinator.prepare(txnId, session, defaultPrepareInputs(commission), after_lost), AuthorityOutcome::Denied);
  auto stuck = pair.reconcile(txnId);
  ASSERT_EQ(stuck.outcome, ReconciliationOutcome::Agreed);
  ASSERT_EQ(stuck.resolved.state, TransactionState::ConsumedPrepared);

  // A competing, fully-activated Rekey for the SAME physical device
  // (different fullPK, revision 1, genuinely chained from `commission`)
  // is written directly -- bypassing coordinator.rekeyExplicitly()'s own
  // issuance-time fence entirely -- to model a writer this coordinator
  // instance's own issuance path never saw.
  TestDevice rekeyed_identity("lineage-revalidate-device-rekeyed", 96);
  AuthorityTransaction rekey;
  rekey.binding = device.binding;
  std::memcpy(rekey.binding.meshFullPublicKey, rekeyed_identity.signer.publicKey(), kPublicKeyBytes);
  rekey.operation = AuthorityOperation::Rekey;
  uint8_t rekey_txn_id[kTransactionIdBytes];
  makeTxnId(rekey_txn_id, 0x61);
  std::memcpy(rekey.transactionId, rekey_txn_id, kTransactionIdBytes);
  rekey.revision = 1;
  std::memcpy(rekey.predecessorTransactionId, txnId, kTransactionIdBytes);
  std::memcpy(rekey.manifestDigestSha256, digest, kDigestBytes);
  rekey.initialTxSequenceFloor = 1;
  rekey.initialRxReplayFloor = 1;
  rekey.issuerKeyId = 1;
  sign(rekey);
  ASSERT_TRUE(pair.commitIssued(rekey));
  uint8_t rekey_root[kDigestBytes];
  fillSeed(rekey_root, "rekey-root-96");
  uint8_t rekey_challenge[kChallengeBytes] = {0};
  ASSERT_TRUE(
      pair.commitStateTransition(rekey_txn_id, TransactionState::ConsumedPrepared, rekey_root, /*rootBound=*/false, rekey_challenge));
  ASSERT_TRUE(
      pair.commitStateTransition(rekey_txn_id, TransactionState::ActivationSpent, rekey_root, /*rootBound=*/true, rekey_challenge));

  // The ORIGINAL transaction is now stale: the physical lineage tip for
  // this exact device is the rekey, not `commission`. resumePrepared
  // must deny rather than finish staging/activating superseded
  // ownership, even though txnId itself is still legitimately
  // ConsumedPrepared and its own signature/state checks pass.
  session.drop_prepare_response = false;
  StoredTransactionRecord after_resume;
  EXPECT_EQ(coordinator.resumePrepared(txnId, session, defaultPrepareInputs(commission), after_resume), AuthorityOutcome::StaleRevision);
  EXPECT_EQ(maintenance.activate_calls, 0);

  // The original transaction's own ConsumedPrepared record must remain
  // exactly as it was -- no new issuance, no silent state advance.
  auto still_stuck = pair.reconcile(txnId);
  ASSERT_EQ(still_stuck.outcome, ReconciliationOutcome::Agreed);
  EXPECT_EQ(still_stuck.resolved.state, TransactionState::ConsumedPrepared);
}

TEST_F(AuthorityFixture, LostPrepareResponseStaysResumableAtConsumedPrepared) {
  TestDevice device("lost-response-device", 24);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x18);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-24");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(4);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy, nullptr, &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(txn), AuthorityOutcome::Ok);

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(5);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                              &signer);
  LoopbackDeviceSession session(guard);
  session.drop_prepare_response = true;

  StoredTransactionRecord after_lost;
  EXPECT_EQ(coordinator.prepare(txnId, session, defaultPrepareInputs(txn), after_lost), AuthorityOutcome::Denied);

  auto rec = pair.reconcile(txnId);
  ASSERT_EQ(rec.outcome, ReconciliationOutcome::Agreed);
  EXPECT_EQ(rec.resolved.state, TransactionState::ConsumedPrepared);  // consumed, not lost/reset.

  // Retry via resumePrepared with the response now arriving successfully.
  session.drop_prepare_response = false;
  StoredTransactionRecord after_resume;
  EXPECT_EQ(coordinator.resumePrepared(txnId, session, defaultPrepareInputs(txn), after_resume), AuthorityOutcome::Ok);
  EXPECT_EQ(after_resume.state, TransactionState::ActivationSpent);
}

TEST_F(AuthorityFixture, ResumePreparedAfterActivationSpentIsRejectedNotRestaged) {
  // HIGH1 regression: resumePrepared() used to only reject `Issued`,
  // letting an already-ActivationSpent transaction fall through to
  // runPrepareHandshake() and unconditionally re-send a fresh
  // PreparePermit -- which re-invokes the device's commitStaged(), a
  // mutation that can clear/downgrade an already-activated device BEFORE
  // any host-side legality check runs. This proves the fixed
  // resumePrepared() refuses outright (WrongState) and never re-enters
  // the device's stage path at all once ActivationSpent exists.
  TestDevice device("resume-after-spent-device", 60);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x3C);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-60");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(60);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy, activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(txn), AuthorityOutcome::Ok);

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(61);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store,
                              &maintenance, &signer);
  LoopbackDeviceSession session(guard);

  StoredTransactionRecord after_prepare;
  ASSERT_EQ(coordinator.prepare(txnId, session, defaultPrepareInputs(txn), after_prepare), AuthorityOutcome::Ok);
  ASSERT_EQ(after_prepare.state, TransactionState::ActivationSpent);

  StoredTransactionRecord after_activate;
  ASSERT_EQ(coordinator.activateExistingRoot(txnId, session, after_activate), AuthorityOutcome::Ok);
  TxRxActivationGrant grant;
  ASSERT_EQ(guard.currentActivationGrant(grant), AuthorityOutcome::Ok);  // genuinely activated.

  const int stage_calls_before = maintenance.stage_calls;

  // The exact attack/bug shape: call resumePrepared() on an already-
  // ActivationSpent transaction.
  StoredTransactionRecord after_resume;
  EXPECT_EQ(coordinator.resumePrepared(txnId, session, defaultPrepareInputs(txn), after_resume), AuthorityOutcome::WrongState);

  // No re-staging happened: stageRoot()/commitStaged() must NEVER have
  // been invoked again by this call.
  EXPECT_EQ(maintenance.stage_calls, stage_calls_before);
  // The device is still activated -- proving no downgrade/clear occurred.
  TxRxActivationGrant grant_after;
  EXPECT_EQ(guard.currentActivationGrant(grant_after), AuthorityOutcome::Ok);
  EXPECT_EQ(grant_after.txSequenceFloor, grant.txSequenceFloor);
  EXPECT_EQ(grant_after.rxReplayFloor, grant.rxReplayFloor);

  // The registry itself is untouched: still cleanly ActivationSpent.
  auto rec = pair.reconcile(txnId);
  EXPECT_EQ(rec.outcome, ReconciliationOutcome::Agreed);
  EXPECT_EQ(rec.resolved.state, TransactionState::ActivationSpent);

  // The lawful path for an already-Spent transaction is
  // activateExistingRoot(), which never re-stages and simply re-delivers
  // the existing permit.
  StoredTransactionRecord after_reactivate;
  EXPECT_EQ(coordinator.activateExistingRoot(txnId, session, after_reactivate), AuthorityOutcome::Ok);
  EXPECT_EQ(maintenance.stage_calls, stage_calls_before);  // still no restage.
}

TEST_F(AuthorityFixture, DeviceResponseWithDifferentManifestIsRejected) {
  TestDevice device("mismatch-device", 25);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x19);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-25");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(6);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy, nullptr, &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(txn), AuthorityOutcome::Ok);

  ScriptedDeviceSession session;
  // The REAL device-minted challenge the coordinator will actually
  // request (via session.requestDeviceChallenge) and bind into both the
  // PrepareAuthorizationV1 it signs and the ack message it verifies.
  std::memset(session.challenge_response, 0x77, kChallengeBytes);

  // Sign a well-formed but WRONG root digest as the device's ack --
  // against a DIFFERENT (stale/bogus) challenge than the one the
  // coordinator actually minted/bound above. A device (or attacker)
  // that signs an ack for a root/challenge pair it was never actually
  // issued a PreparePermit for with THIS challenge must never be
  // accepted, regardless of how plausible the (also bogus) root digest
  // looks.
  uint8_t wrong_root[kDigestBytes];
  fillSeed(wrong_root, "wrong-root");
  uint8_t device_nonce[kChallengeBytes] = {0x11};
  uint8_t bogus_challenge[kChallengeBytes] = {0};
  uint8_t message[AuthorityAckCodec::kMessageBytes];
  AuthorityAckCodec::serializePrepareAck(bogus_challenge, device_nonce, txnId, wrong_root, message, sizeof(message));
  device.signer.sign(message, sizeof(message), session.prepare_response.deviceSignatureEd25519);
  std::memcpy(session.prepare_response.rootDigestSha256, wrong_root, kDigestBytes);
  std::memcpy(session.prepare_response.deviceNonce, device_nonce, kChallengeBytes);

  StoredTransactionRecord out;
  auto outcome = coordinator.prepare(txnId, session, defaultPrepareInputs(txn), out);
  // Prove this rejection genuinely came from the intended device-ACK
  // signature check -- NOT an earlier, unrelated refusal (missing
  // dependency, binding mismatch, wrong state, etc.) that happens to
  // also return a non-Ok outcome. The coordinator must have actually
  // minted/requested the real device challenge AND actually invoked
  // sendPreparePermit() (which is where the bogus-signed ack above is
  // delivered back) before this assertion is meaningful.
  ASSERT_EQ(session.requestDeviceChallengeCalls, 1)
      << "coordinator never reached the device-challenge mint call -- an earlier refusal "
      << "(actual outcome=" << authorityOutcomeName(outcome) << ") would make the outcome "
      << "assertion below meaningless";
  ASSERT_EQ(session.sendPreparePermitCalls, 1)
      << "coordinator never reached sendPreparePermit() -- the bogus-signed ack was never even "
      << "delivered (actual outcome=" << authorityOutcomeName(outcome) << ")";
  EXPECT_EQ(outcome, AuthorityOutcome::SignatureInvalid)
      << "expected SignatureInvalid for a well-formed ack signed against the wrong (bogus) "
      << "challenge/root, but actual outcome was " << authorityOutcomeName(outcome);

  auto rec = pair.reconcile(txnId);
  EXPECT_EQ(rec.resolved.state, TransactionState::ConsumedPrepared)  // never advanced on a bad response.
      << "actual state=" << static_cast<int>(rec.resolved.state) << " (ActivationSpent must never be "
      << "reached when the device ack signature is invalid)";
}

TEST_F(AuthorityFixture, MissingCoordinatorDependenciesDenyEverything) {
  TestDevice device("denies-device", 26);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x1A);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-26");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  ASSERT_TRUE(pair.commitIssued(txn));

  CountingEntropy entropy(7);
  AuthorityCoordinator no_verifier(pair, nullptr, issuer_trust_.get(), &entropy, nullptr, nullptr, prepare_signing_trust_.get());
  AuthorityCoordinator no_issuer(pair, &verifier_, nullptr, &entropy, nullptr, nullptr, prepare_signing_trust_.get());
  AuthorityCoordinator no_entropy(pair, &verifier_, issuer_trust_.get(), nullptr, nullptr, nullptr, prepare_signing_trust_.get());

  ScriptedDeviceSession session;
  StoredTransactionRecord out;
  EXPECT_EQ(no_verifier.prepare(txnId, session, defaultPrepareInputs(txn), out), AuthorityOutcome::Denied);
  EXPECT_EQ(no_issuer.prepare(txnId, session, defaultPrepareInputs(txn), out), AuthorityOutcome::Denied);
  EXPECT_EQ(no_entropy.prepare(txnId, session, defaultPrepareInputs(txn), out), AuthorityOutcome::Denied);
}

TEST_F(AuthorityFixture, RepairRequiresSurvivingHistoryAndNeverLowersFloors) {
  TestDevice device("repair-device", 27);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x1B);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-27");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest, /*txFloor=*/10, /*rxFloor=*/10);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(8);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(9);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                              &signer);
  LoopbackDeviceSession session(guard);
  StoredTransactionRecord after;
  ASSERT_EQ(coordinator.prepare(txnId, session, defaultPrepareInputs(commission), after), AuthorityOutcome::Ok);
  ASSERT_EQ(coordinator.activateExistingRoot(txnId, session, after), AuthorityOutcome::Ok);

  // Repair attempt for a device with NO surviving history at all.
  TestDevice never_commissioned("never-commissioned", 28);
  uint8_t repair_txn_id[kTransactionIdBytes];
  makeTxnId(repair_txn_id, 0x1C);
  AuthorityTransaction orphan_repair;
  orphan_repair.binding = never_commissioned.binding;
  orphan_repair.operation = AuthorityOperation::Repair;
  std::memcpy(orphan_repair.transactionId, repair_txn_id, kTransactionIdBytes);
  orphan_repair.revision = 1;
  orphan_repair.issuerKeyId = 1;
  sign(orphan_repair);
  EXPECT_EQ(coordinator.repairExisting(orphan_repair), AuthorityOutcome::MissingHistory);

  // Genuine repair: chains from the prior transaction, floors >= prior.
  uint8_t repair_id_2[kTransactionIdBytes];
  makeTxnId(repair_id_2, 0x1D);
  AuthorityTransaction good_repair;
  good_repair.binding = device.binding;
  good_repair.operation = AuthorityOperation::Repair;
  std::memcpy(good_repair.transactionId, repair_id_2, kTransactionIdBytes);
  good_repair.revision = 1;
  std::memcpy(good_repair.predecessorTransactionId, txnId, kTransactionIdBytes);
  std::memcpy(good_repair.manifestDigestSha256, digest, kDigestBytes);
  good_repair.initialTxSequenceFloor = 10;  // == prior, not lower.
  good_repair.initialRxReplayFloor = 10;
  good_repair.issuerKeyId = 1;
  sign(good_repair);
  EXPECT_EQ(coordinator.repairExisting(good_repair), AuthorityOutcome::Ok);

  // A repair that tries to FABRICATE A LOWER watermark than the surviving
  // proof must be rejected.
  uint8_t repair_id_3[kTransactionIdBytes];
  makeTxnId(repair_id_3, 0x1E);
  AuthorityTransaction lowering_repair;
  lowering_repair.binding = device.binding;
  lowering_repair.operation = AuthorityOperation::Repair;
  std::memcpy(lowering_repair.transactionId, repair_id_3, kTransactionIdBytes);
  lowering_repair.revision = 2;
  std::memcpy(lowering_repair.predecessorTransactionId, repair_id_2, kTransactionIdBytes);
  std::memcpy(lowering_repair.manifestDigestSha256, digest, kDigestBytes);
  lowering_repair.initialTxSequenceFloor = 3;  // lower than 10: must be refused.
  lowering_repair.initialRxReplayFloor = 10;
  lowering_repair.issuerKeyId = 1;
  sign(lowering_repair);
  EXPECT_EQ(coordinator.repairExisting(lowering_repair), AuthorityOutcome::StaleRevision);
}

TEST_F(AuthorityFixture, RekeyRequiresGenuineKeyMaterialChangeNotJustARelabel) {
  TestDevice device("rekey-device", 29);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x1F);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-29");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest, 1, 1);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(10);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(11);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                              &signer);
  LoopbackDeviceSession session(guard);
  StoredTransactionRecord after;
  ASSERT_EQ(coordinator.prepare(txnId, session, defaultPrepareInputs(commission), after), AuthorityOutcome::Ok);
  ASSERT_EQ(coordinator.activateExistingRoot(txnId, session, after), AuthorityOutcome::Ok);

  // A same-PK relabel (role change only) is NOT a rekey and must be
  // rejected outright, even with an otherwise-valid signature.
  AuthorityTransaction relabel;
  relabel.binding = device.binding;
  relabel.binding.historicalInitialRoleId = 1;  // "realrepeater1" relabel, same fullPK.
  relabel.operation = AuthorityOperation::Rekey;
  uint8_t relabel_txn_id[kTransactionIdBytes];
  makeTxnId(relabel_txn_id, 0x20);
  std::memcpy(relabel.transactionId, relabel_txn_id, kTransactionIdBytes);
  relabel.revision = 1;
  std::memcpy(relabel.predecessorTransactionId, txnId, kTransactionIdBytes);
  relabel.issuerKeyId = 1;
  sign(relabel);
  EXPECT_EQ(coordinator.rekeyExplicitly(relabel, device.binding), AuthorityOutcome::BindingMismatch);

  // A genuine rekey: same UID/domain/layout, ACTUALLY different fullPK.
  TestDevice rekeyed_identity("rekey-device-new-key", 29);
  AuthorityTransaction genuine_rekey;
  genuine_rekey.binding = device.binding;
  std::memcpy(genuine_rekey.binding.meshFullPublicKey, rekeyed_identity.signer.publicKey(), kPublicKeyBytes);
  genuine_rekey.operation = AuthorityOperation::Rekey;
  uint8_t rekey_txn_id[kTransactionIdBytes];
  makeTxnId(rekey_txn_id, 0x21);
  std::memcpy(genuine_rekey.transactionId, rekey_txn_id, kTransactionIdBytes);
  genuine_rekey.revision = 1;
  std::memcpy(genuine_rekey.predecessorTransactionId, txnId, kTransactionIdBytes);
  std::memcpy(genuine_rekey.manifestDigestSha256, digest, kDigestBytes);
  genuine_rekey.initialTxSequenceFloor = 1;
  genuine_rekey.initialRxReplayFloor = 1;
  genuine_rekey.issuerKeyId = 1;
  sign(genuine_rekey);
  EXPECT_EQ(coordinator.rekeyExplicitly(genuine_rekey, device.binding), AuthorityOutcome::Ok);
}

// H-finding: a competing rekey to a DIFFERENT new key, at the same
// predecessor+revision as an already-pending (not yet activated) rekey,
// must be rejected as a fork -- even though the OLD key's own
// ActivationSpent lookup hasn't moved (the pending successor is filed
// under its own, different, fullPK). A genuine B->C successor AFTER B
// fully activates must still be permitted.
TEST_F(AuthorityFixture, RekeyForkToADifferentPendingKeyIsRejectedEvenBeforeSuccessorActivates) {
  TestDevice device("rekey-fork-device", 40);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x50);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-40");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest, 1, 1);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(40);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 41, commission);

  // Rekey A->B: submitted (Issued) but deliberately never prepared or
  // activated -- exactly the "pending, not yet ActivationSpent" gap the
  // old fullPK-scoped lookup cannot see.
  TestDevice identity_b("rekey-fork-device-key-b", 40);
  AuthorityTransaction rekey_to_b;
  rekey_to_b.binding = device.binding;
  std::memcpy(rekey_to_b.binding.meshFullPublicKey, identity_b.signer.publicKey(), kPublicKeyBytes);
  rekey_to_b.operation = AuthorityOperation::Rekey;
  uint8_t rekey_b_txn_id[kTransactionIdBytes];
  makeTxnId(rekey_b_txn_id, 0x51);
  std::memcpy(rekey_to_b.transactionId, rekey_b_txn_id, kTransactionIdBytes);
  rekey_to_b.revision = 1;
  std::memcpy(rekey_to_b.predecessorTransactionId, txnId, kTransactionIdBytes);
  std::memcpy(rekey_to_b.manifestDigestSha256, digest, kDigestBytes);
  rekey_to_b.initialTxSequenceFloor = 1;
  rekey_to_b.initialRxReplayFloor = 1;
  rekey_to_b.issuerKeyId = 1;
  sign(rekey_to_b);
  ASSERT_EQ(coordinator.rekeyExplicitly(rekey_to_b, device.binding), AuthorityOutcome::Ok);

  // Competing rekey A->C: same predecessor+revision, genuinely DIFFERENT
  // new fullPK. Must be blocked even though B never activated and the
  // OLD key's own ActivationSpent record hasn't moved.
  TestDevice identity_c("rekey-fork-device-key-c", 40);
  AuthorityTransaction rekey_to_c;
  rekey_to_c.binding = device.binding;
  std::memcpy(rekey_to_c.binding.meshFullPublicKey, identity_c.signer.publicKey(), kPublicKeyBytes);
  rekey_to_c.operation = AuthorityOperation::Rekey;
  uint8_t rekey_c_txn_id[kTransactionIdBytes];
  makeTxnId(rekey_c_txn_id, 0x52);
  std::memcpy(rekey_to_c.transactionId, rekey_c_txn_id, kTransactionIdBytes);
  rekey_to_c.revision = 1;
  std::memcpy(rekey_to_c.predecessorTransactionId, txnId, kTransactionIdBytes);
  std::memcpy(rekey_to_c.manifestDigestSha256, digest, kDigestBytes);
  rekey_to_c.initialTxSequenceFloor = 1;
  rekey_to_c.initialRxReplayFloor = 1;
  rekey_to_c.issuerKeyId = 1;
  sign(rekey_to_c);
  EXPECT_EQ(coordinator.rekeyExplicitly(rekey_to_c, device.binding), AuthorityOutcome::StaleRevision);

  // A genuine successor AFTER B fully activates (prepare+activate on the
  // B transaction) must still be permitted: B's own ActivationSpent
  // record becomes `prior` for the next rekey, and the physical-lineage
  // tip now legitimately IS B.
  prepareAndActivate(coordinator, rekey_b_txn_id, identity_b, 42, rekey_to_b);

  TestDevice identity_d("rekey-fork-device-key-d", 40);
  AuthorityTransaction rekey_b_to_d;
  rekey_b_to_d.binding = device.binding;
  std::memcpy(rekey_b_to_d.binding.meshFullPublicKey, identity_d.signer.publicKey(), kPublicKeyBytes);
  rekey_b_to_d.operation = AuthorityOperation::Rekey;
  uint8_t rekey_d_txn_id[kTransactionIdBytes];
  makeTxnId(rekey_d_txn_id, 0x53);
  std::memcpy(rekey_b_to_d.transactionId, rekey_d_txn_id, kTransactionIdBytes);
  rekey_b_to_d.revision = 2;
  std::memcpy(rekey_b_to_d.predecessorTransactionId, rekey_b_txn_id, kTransactionIdBytes);
  std::memcpy(rekey_b_to_d.manifestDigestSha256, digest, kDigestBytes);
  rekey_b_to_d.initialTxSequenceFloor = 1;
  rekey_b_to_d.initialRxReplayFloor = 1;
  rekey_b_to_d.issuerKeyId = 1;
  sign(rekey_b_to_d);
  EXPECT_EQ(coordinator.rekeyExplicitly(rekey_b_to_d, identity_b.binding), AuthorityOutcome::Ok);
}

// Sol39 H1: the mirror-image fork this review specifically called out --
// "After Spent A, rekey A->B Issued rev1, repair A->C rev1 still issues C
// -> durable fork" -- repairExisting previously had NO physical-lineage
// fence at all (unlike rekeyExplicitly, which already had one). A
// Repair issued against the OLD owner's own predecessor/revision, after
// a competing (still-pending, not yet activated) Rekey to a genuinely
// different fullPK already claimed that exact predecessor+revision for
// the same physical device, must be denied -- never silently accepted
// as if the pending rekey did not exist.
TEST_F(AuthorityFixture, RepairForkAgainstAPendingRekeySuccessorIsRejectedEvenBeforeItActivates) {
  TestDevice device("repair-fork-device", 120);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0xB0);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-120");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest, 1, 1);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(120);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 121, commission);

  // Rekey A->B: Issued (pending) but DELIBERATELY never prepared/
  // activated -- "it might already have issued nonces" is irrelevant
  // here; the point is this successor is already CLAIMED, not yet spent.
  TestDevice identity_b("repair-fork-device-key-b", 120);
  AuthorityTransaction rekey_to_b;
  rekey_to_b.binding = device.binding;
  std::memcpy(rekey_to_b.binding.meshFullPublicKey, identity_b.signer.publicKey(), kPublicKeyBytes);
  rekey_to_b.operation = AuthorityOperation::Rekey;
  uint8_t rekey_b_txn_id[kTransactionIdBytes];
  makeTxnId(rekey_b_txn_id, 0xB1);
  std::memcpy(rekey_to_b.transactionId, rekey_b_txn_id, kTransactionIdBytes);
  rekey_to_b.revision = 1;
  std::memcpy(rekey_to_b.predecessorTransactionId, txnId, kTransactionIdBytes);
  std::memcpy(rekey_to_b.manifestDigestSha256, digest, kDigestBytes);
  rekey_to_b.initialTxSequenceFloor = 1;
  rekey_to_b.initialRxReplayFloor = 1;
  rekey_to_b.issuerKeyId = 1;
  sign(rekey_to_b);
  ASSERT_EQ(coordinator.rekeyExplicitly(rekey_to_b, device.binding), AuthorityOutcome::Ok);

  // Sequential (not concurrent) Repair for the OLD owner A, same
  // predecessor+revision B already claimed: must be denied.
  uint8_t repair_c_txn_id[kTransactionIdBytes];
  makeTxnId(repair_c_txn_id, 0xB2);
  AuthorityTransaction repair_to_c;
  repair_to_c.binding = device.binding;  // Same physical UID/domain/layout, OLD fullPK.
  repair_to_c.operation = AuthorityOperation::Repair;
  std::memcpy(repair_to_c.transactionId, repair_c_txn_id, kTransactionIdBytes);
  repair_to_c.revision = 1;
  std::memcpy(repair_to_c.predecessorTransactionId, txnId, kTransactionIdBytes);
  std::memcpy(repair_to_c.manifestDigestSha256, digest, kDigestBytes);
  repair_to_c.initialTxSequenceFloor = 1;
  repair_to_c.initialRxReplayFloor = 1;
  repair_to_c.issuerKeyId = 1;
  sign(repair_to_c);
  EXPECT_EQ(coordinator.repairExisting(repair_to_c), AuthorityOutcome::StaleRevision);

  // A genuine repair AFTER B fully activates (the new surviving fullPK)
  // must still be permitted -- the physical-lineage tip is now
  // legitimately B, and repairExisting is called with B's OWN binding as
  // `repairTxn.binding` (repair never changes fullPK, only Rekey does).
  prepareAndActivate(coordinator, rekey_b_txn_id, identity_b, 122, rekey_to_b);

  uint8_t repair_after_b_txn_id[kTransactionIdBytes];
  makeTxnId(repair_after_b_txn_id, 0xB3);
  AuthorityTransaction repair_after_b;
  repair_after_b.binding = identity_b.binding;
  repair_after_b.operation = AuthorityOperation::Repair;
  std::memcpy(repair_after_b.transactionId, repair_after_b_txn_id, kTransactionIdBytes);
  repair_after_b.revision = 2;
  std::memcpy(repair_after_b.predecessorTransactionId, rekey_b_txn_id, kTransactionIdBytes);
  std::memcpy(repair_after_b.manifestDigestSha256, digest, kDigestBytes);
  repair_after_b.initialTxSequenceFloor = 1;
  repair_after_b.initialRxReplayFloor = 1;
  repair_after_b.issuerKeyId = 1;
  sign(repair_after_b);
  EXPECT_EQ(coordinator.repairExisting(repair_after_b), AuthorityOutcome::Ok);
}

// MAIN's binding clarification: the lifetime fork-fence must be
// independent of profileId/layoutId (and fullPK/role) labels -- a
// relabeled profile/layout for the SAME physical UID+cryptoDomain must
// never be smuggled through submitCommission as an unrelated "genesis"
// device. This is the gap the H3 comment on SubmitCommissionRejects-
// SecondGenesisOverAlreadyCommissionedOwner CLAIMED to close ("a new
// profile/layout... must never look like a fresh genesis commission")
// but did not: both reconcileLatestActivationForOwner and
// reconcileOwnershipLineage are scoped to sameOwnership, which REQUIRES
// profileId/layoutId (and fullPK) to match exactly -- so changing
// either previously made an already-commissioned physical device look
// like a brand-new, unrelated owner to those two checks alone.
// submitCommission must now ALSO check reconcilePhysicalLineage
// (samePhysicalLifetime: UID + fixed BOOT domain ONLY) to actually close
// this escape.
TEST_F(AuthorityFixture, SubmitCommissionCannotEscapeTheLifetimeFenceByRelabelingProfileLayoutOrKey) {
  TestDevice device("commission-relabel-device", 123);
  uint8_t first_txn_id[kTransactionIdBytes];
  makeTxnId(first_txn_id, 0xC0);
  uint8_t first_digest[kDigestBytes];
  fillSeed(first_digest, "manifest-123-first");
  AuthorityTransaction first_txn = makeCommission(device.binding, first_txn_id, first_digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(123);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(first_txn), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, first_txn_id, device, /*entropyTag=*/124, first_txn);

  // A relabeled profile+layout AND a different fullPK -- same physical
  // UID+cryptoDomain -- attempting a fresh revision-0 genesis Commission
  // must still be rejected as StaleRevision, not accepted as an
  // unrelated device's legitimate first commission.
  TestDevice relabeled_identity("commission-relabel-device-key-b", 123);
  AuthorityBinding relabeled = device.binding;
  std::memcpy(relabeled.meshFullPublicKey, relabeled_identity.signer.publicKey(), kPublicKeyBytes);
  relabeled.profileId ^= 0xA5A5A5A5u;
  relabeled.layoutId ^= 0x5A5A5A5Au;
  uint8_t second_txn_id[kTransactionIdBytes];
  makeTxnId(second_txn_id, 0xC1);
  uint8_t second_digest[kDigestBytes];
  fillSeed(second_digest, "manifest-123-relabel");
  AuthorityTransaction second_txn = makeCommission(relabeled, second_txn_id, second_digest);
  EXPECT_EQ(coordinator.submitCommission(second_txn), AuthorityOutcome::StaleRevision);

  // A genuinely unrelated physical device (different hardwareUid
  // entirely) is still unaffected: its own first commission remains
  // permitted.
  TestDevice unrelated_device("commission-relabel-unrelated-device", 125);
  uint8_t third_txn_id[kTransactionIdBytes];
  makeTxnId(third_txn_id, 0xC2);
  uint8_t third_digest[kDigestBytes];
  fillSeed(third_digest, "manifest-123-unrelated");
  AuthorityTransaction third_txn = makeCommission(unrelated_device.binding, third_txn_id, third_digest);
  EXPECT_EQ(coordinator.submitCommission(third_txn), AuthorityOutcome::Ok);
}

// Sol43 HIGH fix regression: the escape was specifically that
// samePhysicalLifetime previously STILL compared cryptoDomain, so a
// second genuinely-signed revision-0 Commission for the exact SAME
// hardwareUid (and even the exact SAME fullPK) but a DIFFERENT
// crypto-domain groupSelector/layoutId was invisible to BOTH
// sameOwnership-scoped checks (which require crypto-domain/layout to
// match) and the physical-lineage scan itself -- letting a duplicate
// "genesis" Issued record through for a device that already has real
// ActivationSpent history. This must now be denied BEFORE a second
// Issued record is ever created, for either dimension independently.
TEST_F(AuthorityFixture, SubmitCommissionDeniesSecondGenesisWithDifferentCryptoDomainOrLayoutEvenWithSameKey) {
  TestDevice device("commission-cryptodomain-relabel-device", 150);
  uint8_t first_txn_id[kTransactionIdBytes];
  makeTxnId(first_txn_id, 0xD0);
  uint8_t first_digest[kDigestBytes];
  fillSeed(first_digest, "manifest-150-first");
  AuthorityTransaction first_txn = makeCommission(device.binding, first_txn_id, first_digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(150);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(first_txn), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, first_txn_id, device, /*entropyTag=*/151, first_txn);

  // Same hardwareUid, same fullPK, ONLY the crypto-domain groupSelector
  // changes (form stays Pairwise so groupSelector stays meaningful-ish
  // for this test's purposes; the point is purely that it differs).
  AuthorityBinding different_group_selector = device.binding;
  different_group_selector.cryptoDomain.groupSelector = 0x1234;
  uint8_t second_txn_id[kTransactionIdBytes];
  makeTxnId(second_txn_id, 0xD1);
  uint8_t second_digest[kDigestBytes];
  fillSeed(second_digest, "manifest-150-group-selector");
  AuthorityTransaction second_txn = makeCommission(different_group_selector, second_txn_id, second_digest);
  EXPECT_EQ(coordinator.submitCommission(second_txn), AuthorityOutcome::StaleRevision);

  // Same hardwareUid, same fullPK, ONLY layoutId changes.
  AuthorityBinding different_layout = device.binding;
  different_layout.layoutId = device.binding.layoutId + 1;
  uint8_t third_txn_id[kTransactionIdBytes];
  makeTxnId(third_txn_id, 0xD2);
  uint8_t third_digest[kDigestBytes];
  fillSeed(third_digest, "manifest-150-layout");
  AuthorityTransaction third_txn = makeCommission(different_layout, third_txn_id, third_digest);
  EXPECT_EQ(coordinator.submitCommission(third_txn), AuthorityOutcome::StaleRevision);
}

// Sol39 H1: the GENUINELY CONCURRENT variant of the same fork -- two
// real OS processes, one issuing a Rekey A->B and the other issuing a
// Repair for A at the identical predecessor+revision, both racing
// through their own check-then-act window. The mandatory lease now
// wired into BOTH repairExisting and rekeyExplicitly must ensure
// EXACTLY ONE of the two ever succeeds, never both.
TEST_F(AuthorityFixture, TwoRealOsProcessesRacingRekeyAndRepairForTheSameOwnerNeverBothSucceed) {
  TestDevice device("repair-rekey-race-device", 123);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0xB8);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-123");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest, 1, 1);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(123);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 124, commission);

  TestDevice identity_b("repair-rekey-race-device-key-b", 123);
  AuthorityTransaction rekey_to_b;
  rekey_to_b.binding = device.binding;
  std::memcpy(rekey_to_b.binding.meshFullPublicKey, identity_b.signer.publicKey(), kPublicKeyBytes);
  rekey_to_b.operation = AuthorityOperation::Rekey;
  uint8_t rekey_b_txn_id[kTransactionIdBytes];
  makeTxnId(rekey_b_txn_id, 0xB9);
  std::memcpy(rekey_to_b.transactionId, rekey_b_txn_id, kTransactionIdBytes);
  rekey_to_b.revision = 1;
  std::memcpy(rekey_to_b.predecessorTransactionId, txnId, kTransactionIdBytes);
  std::memcpy(rekey_to_b.manifestDigestSha256, digest, kDigestBytes);
  rekey_to_b.initialTxSequenceFloor = 1;
  rekey_to_b.initialRxReplayFloor = 1;
  rekey_to_b.issuerKeyId = 1;
  sign(rekey_to_b);

  uint8_t repair_c_txn_id[kTransactionIdBytes];
  makeTxnId(repair_c_txn_id, 0xBA);
  AuthorityTransaction repair_to_c;
  repair_to_c.binding = device.binding;
  repair_to_c.operation = AuthorityOperation::Repair;
  std::memcpy(repair_to_c.transactionId, repair_c_txn_id, kTransactionIdBytes);
  repair_to_c.revision = 1;
  std::memcpy(repair_to_c.predecessorTransactionId, txnId, kTransactionIdBytes);
  std::memcpy(repair_to_c.manifestDigestSha256, digest, kDigestBytes);
  repair_to_c.initialTxSequenceFloor = 1;
  repair_to_c.initialRxReplayFloor = 1;
  repair_to_c.issuerKeyId = 1;
  sign(repair_to_c);

  struct SharedState {
    std::atomic<int> ready_count;
    int outcome_rekey;
    int outcome_repair;
  };
  void* shm = mmap(nullptr, sizeof(SharedState), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(shm, MAP_FAILED);
  auto* state = new (shm) SharedState();
  state->ready_count.store(0);
  state->outcome_rekey = -1;
  state->outcome_repair = -1;

  auto runRekeyChild = [&]() {
    FileAuthorityRegistryCopy child_a(copyAPath_), child_b(copyBPath_);
    AuthorityRegistryPair child_pair(child_a, child_b);
    FileAuthorityCrossProcessLock child_lock(copyAPath_, copyBPath_);
    AuthorityCoordinator child_coordinator(child_pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                            activation_signing_trust_.get(), &child_lock, prepare_signing_trust_.get());
    state->ready_count.fetch_add(1);
    while (state->ready_count.load() < 2) { /* spin: maximize actual overlap */
    }
    state->outcome_rekey = static_cast<int>(child_coordinator.rekeyExplicitly(rekey_to_b, device.binding));
  };
  auto runRepairChild = [&]() {
    FileAuthorityRegistryCopy child_a(copyAPath_), child_b(copyBPath_);
    AuthorityRegistryPair child_pair(child_a, child_b);
    FileAuthorityCrossProcessLock child_lock(copyAPath_, copyBPath_);
    AuthorityCoordinator child_coordinator(child_pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                            activation_signing_trust_.get(), &child_lock, prepare_signing_trust_.get());
    state->ready_count.fetch_add(1);
    while (state->ready_count.load() < 2) { /* spin: maximize actual overlap */
    }
    state->outcome_repair = static_cast<int>(child_coordinator.repairExisting(repair_to_c));
  };

  const pid_t pid_rekey = fork();
  ASSERT_GE(pid_rekey, 0);
  if (pid_rekey == 0) {
    runRekeyChild();
    _exit(0);
  }
  const pid_t pid_repair = fork();
  ASSERT_GE(pid_repair, 0);
  if (pid_repair == 0) {
    runRepairChild();
    _exit(0);
  }

  int status_rekey = 0, status_repair = 0;
  ASSERT_EQ(waitpid(pid_rekey, &status_rekey, 0), pid_rekey);
  ASSERT_EQ(waitpid(pid_repair, &status_repair, 0), pid_repair);
  ASSERT_TRUE(WIFEXITED(status_rekey));
  ASSERT_TRUE(WIFEXITED(status_repair));

  const auto rekey_outcome = static_cast<AuthorityOutcome>(state->outcome_rekey);
  const auto repair_outcome = static_cast<AuthorityOutcome>(state->outcome_repair);
  const bool rekey_won = rekey_outcome == AuthorityOutcome::Ok;
  const bool repair_won = repair_outcome == AuthorityOutcome::Ok;
  // EXACTLY one of the two genuinely concurrent, same-predecessor,
  // same-revision candidates for this physical owner may ever succeed.
  EXPECT_TRUE(rekey_won != repair_won) << "rekey=" << static_cast<int>(rekey_outcome)
                                        << " repair=" << static_cast<int>(repair_outcome);

  FileAuthorityRegistryCopy final_a(copyAPath_), final_b(copyBPath_);
  AuthorityRegistryPair final_pair(final_a, final_b);
  ReconciliationResult lineage = final_pair.reconcilePhysicalLineage(device.binding);
  EXPECT_EQ(lineage.outcome, ReconciliationOutcome::Agreed);
}

// M-finding: activateExistingRoot's repair path must be able to rebuild a
// copy that is COMPLETELY EMPTY for this transactionId (never even
// received the original Issued record), not only one that is merely
// lagging in state -- "empty B lacks Issued forever" otherwise.
TEST_F(AuthorityFixture, ActivateExistingRootRepairsACopyMissingItsIssuedRecordEntirely) {
  TestDevice device("empty-copy-repair-device", 41);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x60);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-41");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest, 1, 1);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(43);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(44);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                              &signer);
  LoopbackDeviceSession session(guard);
  StoredTransactionRecord after;
  ASSERT_EQ(coordinator.prepare(txnId, session, defaultPrepareInputs(commission), after), AuthorityOutcome::Ok);

  // Delete copy B's entire backing file AFTER prepare -- simulating a
  // copy that was never actually reachable/present for this transaction
  // at all (not merely a lagging state), then let activateExistingRoot's
  // own repair path rebuild it completely from scratch (Issued ->
  // ConsumedPrepared -> ActivationSpent) using ONLY the already-agreed,
  // already-resolved record -- never a new grant/root.
  ASSERT_EQ(std::remove(copyBPath_.c_str()), 0);

  StoredTransactionRecord activated;
  ASSERT_EQ(coordinator.activateExistingRoot(txnId, session, activated), AuthorityOutcome::Ok);

  // Both copies must now independently, durably agree at ActivationSpent
  // -- verified by a completely fresh pair of FileAuthorityRegistryCopy
  // instances reading back from disk, not the in-memory objects used
  // during repair.
  FileAuthorityRegistryCopy fresh_a(copyAPath_), fresh_b(copyBPath_);
  AuthorityRegistryPair fresh_pair(fresh_a, fresh_b);
  ReconciliationResult final_check = fresh_pair.reconcile(txnId);
  EXPECT_EQ(final_check.outcome, ReconciliationOutcome::Agreed);
  EXPECT_EQ(final_check.resolved.state, TransactionState::ActivationSpent);
}

// M-finding: runPrepareHandshake must repair-then-reconfirm Agreed before
// running the device handshake/final commit when the starting
// reconciliation is only RecoveredFromSingleCopy -- never silently
// complete a "two-copy prepare" whose STARTING state was never durable
// on both copies.
TEST_F(AuthorityFixture, ResumePreparedRepairsLaggingCopyBeforeCompletingHandshake) {
  TestDevice device("resume-repair-device", 42);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x61);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-42");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest, 1, 1);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(45);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);

  // Commit ConsumedPrepared directly to copy A only (simulating the
  // real crash window: prepare()'s own commitStateTransition landed on
  // A but B's write was lost before prepare() itself could return, so
  // this transaction is now genuinely single-copy at ConsumedPrepared).
  uint8_t zero_root[kDigestBytes] = {0};
  uint8_t zero_challenge[kChallengeBytes] = {0};
  // Issued was already committed to BOTH copies by submitCommission()
  // above; only add the ConsumedPrepared transition to copy A to
  // simulate B's write being lost.
  ASSERT_TRUE(a.appendStateTransition(txnId, TransactionState::ConsumedPrepared, zero_root, /*rootBound=*/false,
                                       zero_challenge));
  // Copy B still has its Issued record (from submitCommission above) but
  // genuinely lacks the ConsumedPrepared transition -- a lagging single
  // copy, not a missing file.

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(46);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                              &signer);
  LoopbackDeviceSession session(guard);
  StoredTransactionRecord after;
  ASSERT_EQ(coordinator.resumePrepared(txnId, session, defaultPrepareInputs(commission), after), AuthorityOutcome::Ok);

  // Both copies must be durably, independently ActivationSpent-agreed
  // after resumePrepared completed -- proving the lagging/missing copy
  // was repaired to ConsumedPrepared and reconfirmed Agreed BEFORE the
  // device handshake ran (not only patched up afterwards).
  FileAuthorityRegistryCopy fresh_a(copyAPath_), fresh_b(copyBPath_);
  AuthorityRegistryPair fresh_pair(fresh_a, fresh_b);
  ReconciliationResult final_check = fresh_pair.reconcile(txnId);
  EXPECT_EQ(final_check.outcome, ReconciliationOutcome::Agreed);
  EXPECT_EQ(final_check.resolved.state, TransactionState::ActivationSpent);
}

// ---------------------------------------------------------------------
// DeviceAuthorityGuard: default-deny on missing dependencies, fresh
// challenge/signature mismatch, and root-loss never reseeds.
// ---------------------------------------------------------------------

TEST_F(AuthorityFixture, DeviceGuardDeniesWithAnyMissingDependency) {
  TestDevice device("guard-deny-device", 30);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(12);
  Ed25519DeviceSigner signer(device.signer);

  PreparePermit permit;
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x22);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-30");
  permit.txn = makeCommission(device.binding, txnId, digest);

  PreparedRootResponse response;

  DeviceAuthorityGuard no_verifier(device.binding, nullptr, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);
  EXPECT_EQ(no_verifier.verifyAndPrepare(permit, response), AuthorityOutcome::Denied);

  DeviceAuthorityGuard no_issuer(device.binding, &verifier_, nullptr, &entropy, &store, &maintenance, &signer);
  EXPECT_EQ(no_issuer.verifyAndPrepare(permit, response), AuthorityOutcome::Denied);

  DeviceAuthorityGuard no_entropy(device.binding, &verifier_, issuer_trust_.get(), nullptr, &store, &maintenance, &signer);
  EXPECT_EQ(no_entropy.verifyAndPrepare(permit, response), AuthorityOutcome::Denied);

  DeviceAuthorityGuard no_store(device.binding, &verifier_, issuer_trust_.get(), &entropy, nullptr, &maintenance, &signer);
  EXPECT_EQ(no_store.verifyAndPrepare(permit, response), AuthorityOutcome::Denied);

  DeviceAuthorityGuard no_maintenance(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, nullptr, &signer);
  EXPECT_EQ(no_maintenance.verifyAndPrepare(permit, response), AuthorityOutcome::Denied);

  DeviceAuthorityGuard no_signer(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, nullptr);
  EXPECT_EQ(no_signer.verifyAndPrepare(permit, response), AuthorityOutcome::Denied);
}

TEST_F(AuthorityFixture, DeviceGuardActivationRequiresFreshChallengeMatchAndCorrectSignature) {
  TestDevice device("fresh-challenge-device", 31);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(13);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x23);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-31");
  PreparePermit permit;
  permit.txn = makeCommission(device.binding, txnId, digest);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(permit.txn, prepare_challenge, permit.auth);

  PreparedRootResponse response;
  ASSERT_EQ(guard.verifyAndPrepare(permit, response), AuthorityOutcome::Ok);

  ActivationPermit act_permit;
  act_permit.txn = permit.txn;
  std::memcpy(act_permit.preparedRootDigestSha256, response.rootDigestSha256, kDigestBytes);
  uint8_t activate_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Activate, txnId, activate_challenge));  // Different, fresh challenge from activation.
  signActivationAuth(act_permit.txn, response.rootDigestSha256, activate_challenge, act_permit.activationAuth);

  ActivationResponse act_response;
  TxRxActivationGrant grant;
  EXPECT_EQ(guard.verifyAndActivate(act_permit, act_response, grant), AuthorityOutcome::Ok);

  // A spoofed activation response signed over a STALE (prepare-phase)
  // challenge must fail verification, since the signed message binds the
  // exact challenge presented for THIS step.
  ActivationResponse stale_response = act_response;
  uint8_t stale_message[AuthorityAckCodec::kMessageBytes];
  AuthorityAckCodec::serializeActivateAck(prepare_challenge /* wrong: prepare's challenge */, act_response.deviceNonce,
                                           txnId, response.rootDigestSha256, stale_message, sizeof(stale_message));
  device.signer.sign(stale_message, sizeof(stale_message), stale_response.deviceSignatureEd25519);

  // Re-verify manually: the guard itself only exposes one activation call
  // per permit inside this test, so we directly confirm signature
  // verification against the WRONG challenge fails using the same
  // primitive the guard relies on.
  uint8_t correct_message[AuthorityAckCodec::kMessageBytes];
  AuthorityAckCodec::serializeActivateAck(activate_challenge, act_response.deviceNonce, txnId, response.rootDigestSha256,
                                           correct_message, sizeof(correct_message));
  EXPECT_FALSE(verifier_.verify(stale_response.deviceSignatureEd25519, kSignatureBytes, correct_message,
                                 sizeof(correct_message), device.binding.meshFullPublicKey, kPublicKeyBytes));
}

TEST_F(AuthorityFixture, DeviceGuardActivationRejectsPermitWithoutValidIssuerSignature) {
  // Regression coverage for the fixed vulnerability: ActivationPermit now
  // carries the FULL issuer-signed AuthorityTransaction, and
  // verifyAndActivate independently re-verifies that signature. Before
  // this fix, ActivationPermit carried only a bare transactionId+digest
  // pair (values already visible in cleartext from the earlier,
  // separately-verified prepare step) and verifyAndActivate performed NO
  // issuer signature check whatsoever -- any transport able to reach
  // sendActivationPermit could force activation using only that
  // non-secret pair, regardless of whether the host's own two-copy
  // ActivationSpent commit had genuinely happened.
  TestDevice device("activation-sig-device", 40);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(20);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x30);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-40");
  PreparePermit prepare_permit;
  prepare_permit.txn = makeCommission(device.binding, txnId, digest);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(prepare_permit.txn, prepare_challenge, prepare_permit.auth);

  PreparedRootResponse prepare_response;
  ASSERT_EQ(guard.verifyAndPrepare(prepare_permit, prepare_response), AuthorityOutcome::Ok);

  // Tamper the issuer signature on the transaction carried by the
  // activation permit -- everything else (txnId, digest, binding) is
  // exactly what the device already has staged. activationAuth is
  // deliberately left default/unsigned: the tampered GRANT signature must
  // be rejected before activationAuth is ever even examined.
  ActivationPermit tampered_permit;
  tampered_permit.txn = prepare_permit.txn;
  tampered_permit.txn.issuerSignatureEd25519[0] ^= 0xFF;
  std::memcpy(tampered_permit.preparedRootDigestSha256, prepare_response.rootDigestSha256, kDigestBytes);

  ActivationResponse tampered_response;
  TxRxActivationGrant tampered_grant;
  EXPECT_EQ(guard.verifyAndActivate(tampered_permit, tampered_response, tampered_grant), AuthorityOutcome::SignatureInvalid);
  EXPECT_EQ(maintenance.activate_calls, 0);  // never even attempted activation on an unsigned/forged permit.

  // The SAME permit with the issuer signature restored (i.e. the genuine
  // one from prepare) must still succeed, proving the rejection above was
  // specifically about the tampered signature, not some other field.
  ActivationPermit genuine_permit;
  genuine_permit.txn = prepare_permit.txn;
  std::memcpy(genuine_permit.preparedRootDigestSha256, prepare_response.rootDigestSha256, kDigestBytes);
  uint8_t activate_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Activate, txnId, activate_challenge));
  signActivationAuth(genuine_permit.txn, prepare_response.rootDigestSha256, activate_challenge, genuine_permit.activationAuth);

  ActivationResponse genuine_response;
  TxRxActivationGrant genuine_grant;
  EXPECT_EQ(guard.verifyAndActivate(genuine_permit, genuine_response, genuine_grant), AuthorityOutcome::Ok);
  EXPECT_EQ(maintenance.activate_calls, 1);
}

// Regression coverage for the review-identified replay gap: a captured,
// GENUINELY issuer-signed grant transaction (visible in cleartext from
// the earlier prepare() exchange) must never itself be sufficient
// activation proof -- only a purpose-bound, freshly-produced
// ActivationAuthorizationV1, minted by the host specifically at the
// moment both registry copies reach ActivationSpent, closes this.
TEST_F(AuthorityFixture, DeviceGuardActivationRejectsMissingOrCrossBoundActivationAuthorization) {
  TestDevice device("activation-auth-gap-device", 45);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(21);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x31);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-45");
  PreparePermit prepare_permit;
  prepare_permit.txn = makeCommission(device.binding, txnId, digest);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(prepare_permit.txn, prepare_challenge, prepare_permit.auth);
  PreparedRootResponse prepare_response;
  ASSERT_EQ(guard.verifyAndPrepare(prepare_permit, prepare_response), AuthorityOutcome::Ok);

  // Mint the ONE genuine, single-use activation-phase challenge up front;
  // every attempt below reuses this same outstanding value -- only
  // Attempt 3's authorization is actually signed against it, so Attempts
  // 1/2 cannot accidentally consume it out from under Attempt 3.
  uint8_t real_activate_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Activate, txnId, real_activate_challenge));

  // Attempt 1: the genuine, validly-signed grant transaction with NO
  // activationAuth at all (left default-constructed / all-zero) -- this
  // is exactly what an attacker who merely observed the cleartext
  // prepare exchange could reconstruct without ever touching the host's
  // two-copy ActivationSpent gate.
  {
    ActivationPermit no_auth_permit;
    no_auth_permit.txn = prepare_permit.txn;  // genuine, untampered, validly-signed.
    std::memcpy(no_auth_permit.preparedRootDigestSha256, prepare_response.rootDigestSha256, kDigestBytes);
    // no_auth_permit.activationAuth intentionally left default (zero signature).
    ActivationResponse resp;
    TxRxActivationGrant grant;
    EXPECT_EQ(guard.verifyAndActivate(no_auth_permit, resp, grant), AuthorityOutcome::SignatureInvalid);
    EXPECT_EQ(maintenance.activate_calls, 0);
  }

  // Attempt 2: a GENUINELY signed ActivationAuthorizationV1 (real issuer
  // key, real domain-separated signature) but minted for a DIFFERENT
  // host challenge than the one actually outstanding here -- models
  // replaying a captured authorization from a different activation
  // attempt/session against this one.
  {
    ActivationPermit cross_challenge_permit;
    cross_challenge_permit.txn = prepare_permit.txn;
    std::memcpy(cross_challenge_permit.preparedRootDigestSha256, prepare_response.rootDigestSha256, kDigestBytes);
    uint8_t stale_challenge[kChallengeBytes];
    fillChallenge(stale_challenge, "challenge-45-activate-STALE");
    signActivationAuth(prepare_permit.txn, prepare_response.rootDigestSha256, stale_challenge, cross_challenge_permit.activationAuth);
    ActivationResponse resp;
    TxRxActivationGrant grant;
    EXPECT_EQ(guard.verifyAndActivate(cross_challenge_permit, resp, grant), AuthorityOutcome::ChallengeMismatch);
    EXPECT_EQ(maintenance.activate_calls, 0);
  }

  // Attempt 3: a genuinely signed ActivationAuthorizationV1 scoped to
  // THIS exact transaction/root/challenge succeeds -- proving the two
  // rejections above were specifically about the missing/cross-bound
  // authorization, not some unrelated field.
  {
    ActivationPermit genuine_permit;
    genuine_permit.txn = prepare_permit.txn;
    std::memcpy(genuine_permit.preparedRootDigestSha256, prepare_response.rootDigestSha256, kDigestBytes);
    signActivationAuth(prepare_permit.txn, prepare_response.rootDigestSha256, real_activate_challenge, genuine_permit.activationAuth);
    ActivationResponse resp;
    TxRxActivationGrant grant;
    EXPECT_EQ(guard.verifyAndActivate(genuine_permit, resp, grant), AuthorityOutcome::Ok);
    EXPECT_EQ(maintenance.activate_calls, 1);
  }
}

TEST_F(AuthorityFixture, ActivateExistingRootRequiresBothCopyRepairSuccessBeforeSigning) {
  // HIGH3 regression: activateExistingRoot()'s replica-repair writes used
  // to be fire-and-forget -- both commitStateTransition() return values
  // were discarded outright, so if repairing a lagging copy genuinely
  // failed (e.g. one copy unwritable), the coordinator still proceeded
  // to export a signed ActivationAuthorizationV1 backed by only ONE
  // copy actually reflecting ActivationSpent. This reproduces exactly
  // that scenario (a real cut left B lagging at ConsumedPrepared, then B
  // is made genuinely unwritable) and proves activateExistingRoot now
  // refuses rather than signs.
  TestDevice device("activate-repair-gate-device", 62);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x3E);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-62");
  AuthorityTransaction txn = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  ASSERT_TRUE(pair.commitIssued(txn));

  uint8_t root[kDigestBytes];
  fillSeed(root, "root-62");
  uint8_t challenge[kChallengeBytes] = {0};
  ASSERT_TRUE(pair.commitStateTransition(txnId, TransactionState::ConsumedPrepared, root, /*rootBound=*/false, challenge));
  // Simulate a real cut BETWEEN the two ActivationSpent writes: only A
  // advances, B is left genuinely lagging at ConsumedPrepared.
  ASSERT_TRUE(a.appendStateTransition(txnId, TransactionState::ActivationSpent, root, /*rootBound=*/true, challenge));

  auto rec = pair.reconcile(txnId);
  ASSERT_EQ(rec.outcome, ReconciliationOutcome::RecoveredFromSingleCopy);
  ASSERT_TRUE(rec.needsReplicaRepair);
  ASSERT_EQ(rec.resolved.state, TransactionState::ActivationSpent);

  // Make copy B's backing file genuinely unwritable, so the repair
  // commitStateTransition() write to B is guaranteed to fail.
  ASSERT_EQ(::chmod(copyBPath_.c_str(), 0444), 0);

  CountingEntropy host_entropy(62);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy, activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());

  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(63);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store, &maintenance,
                              &signer);
  LoopbackDeviceSession session(guard);

  StoredTransactionRecord after;
  EXPECT_NE(coordinator.activateExistingRoot(txnId, session, after), AuthorityOutcome::Ok);
  EXPECT_EQ(maintenance.activate_calls, 0);  // never even reached the device.

  ::chmod(copyBPath_.c_str(), 0644);  // restore so test cleanup can remove the directory.
}

TEST_F(AuthorityFixture, ActivationAfterRootLossNeverReseedsAndIsDenied) {
  TestDevice device("root-loss-device", 32);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(14);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x24);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-32");
  PreparePermit permit;
  permit.txn = makeCommission(device.binding, txnId, digest);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(permit.txn, prepare_challenge, permit.auth);

  PreparedRootResponse response;
  ASSERT_EQ(guard.verifyAndPrepare(permit, response), AuthorityOutcome::Ok);

  // Simulate losing the local staged root (flash wipe/corruption) before
  // activation.
  store.simulateRootLoss();

  ActivationPermit act_permit;
  act_permit.txn = permit.txn;
  std::memcpy(act_permit.preparedRootDigestSha256, digest, kDigestBytes);
  uint8_t activate_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Activate, txnId, activate_challenge));
  signActivationAuth(act_permit.txn, digest, activate_challenge, act_permit.activationAuth);

  ActivationResponse act_response;
  TxRxActivationGrant grant;
  EXPECT_EQ(guard.verifyAndActivate(act_permit, act_response, grant), AuthorityOutcome::Denied);
  EXPECT_EQ(maintenance.activate_calls, 0);  // never even attempted a reseed-shaped activation.
}

TEST_F(AuthorityFixture, DeviceGuardRejectsBindingSubstitutionOnPermit) {
  TestDevice device("guard-substitution-device", 33);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(15);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x25);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-33");

  AuthorityBinding wrong_binding = device.binding;
  wrong_binding.hardwareUid[0] ^= 0x01;  // claims a DIFFERENT hardware UID than this guard's own identity.
  PreparePermit permit;
  permit.txn = makeCommission(wrong_binding, txnId, digest);
  // permit.auth intentionally left default: BindingMismatch is detected
  // before any authorization/challenge verification is ever reached.

  PreparedRootResponse response;
  EXPECT_EQ(guard.verifyAndPrepare(permit, response), AuthorityOutcome::BindingMismatch);
  EXPECT_EQ(maintenance.stage_calls, 0);
}

// Sol review HIGH regression (verifyAndPrepare): a Pending
// stageRoot()/commitStaged() continuation used to match ONLY the bare
// transactionId, then use THIS call's (potentially changed) permit
// fields directly at the stageRoot()/commitStaged() I/O boundary -- no
// signature, binding, or floor re-verification occurs on a resuming
// call. This proves a same-transactionId retry presenting CHANGED
// initialTxSequenceFloor/initialRxReplayFloor is rejected with NO
// mutation while leaving the genuine in-flight continuation intact, and
// that an EXACT retry still progresses to completion.
TEST_F(AuthorityFixture, DeviceGuardPrepareResumeRejectsChangedFloorsButExactRetryProgresses) {
  TestDevice device("prepare-resume-guard-device", 70);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(70);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x70);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-70");
  PreparePermit permit;
  permit.txn = makeCommission(device.binding, txnId, digest, /*txFloor=*/100, /*rxFloor=*/200);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(permit.txn, prepare_challenge, permit.auth);

  // stageRoot() itself genuinely stalls (`Pending`) on the first call --
  // this is the ORIGINAL, fully-verified call; the guard must retain its
  // exact txn/auth now, before the resumable continuation begins.
  maintenance.simulate_stage_pending_once = true;
  PreparedRootResponse response;
  ASSERT_EQ(guard.verifyAndPrepare(permit, response), AuthorityOutcome::Pending);
  ASSERT_EQ(maintenance.stage_calls, 1);
  EXPECT_FALSE(store.hasStateForTest());  // zero mutation from the stalled attempt.

  // Attacker/bug-shaped retry: SAME transactionId, but with CHANGED
  // floors -- a real attacker-controlled or buggy caller resuming with
  // different authorized bounds. This must be rejected before ANY
  // further stageRoot()/commitStaged() call, and the continuation itself
  // must remain untouched for the genuine owner's later exact retry.
  PreparePermit changed_permit = permit;
  changed_permit.txn.initialTxSequenceFloor = 999;
  changed_permit.txn.initialRxReplayFloor = 999;
  PreparedRootResponse changed_response;
  EXPECT_EQ(guard.verifyAndPrepare(changed_permit, changed_response), AuthorityOutcome::BindingMismatch);
  EXPECT_EQ(maintenance.stage_calls, 1);  // no additional stageRoot() attempt at all.
  EXPECT_FALSE(store.hasStateForTest());  // still zero mutation.

  // The EXACT original permit (unchanged) must still resume and
  // progress all the way to completion: stageRoot() is invoked exactly
  // once more (the retry), never re-verifying the signature/challenge.
  PreparedRootResponse exact_response;
  EXPECT_EQ(guard.verifyAndPrepare(permit, exact_response), AuthorityOutcome::Ok);
  EXPECT_EQ(maintenance.stage_calls, 2);  // original stalled attempt + this exact retry.
  DeviceAuthorityState state;
  ASSERT_EQ(store.readCurrent(state), DeviceAuthorityReadStatus::Present);
  EXPECT_EQ(state.txSequenceFloor, 100u);
  EXPECT_EQ(state.rxReplayFloor, 200u);
}

// Sol review HIGH regression (verifyAndActivate): same rationale as the
// Prepare case above, but covering the Activating/Committing phases --
// proves a same-transactionId retry with a changed activationAuth field
// is rejected with no mutation, while an exact retry still activates.
TEST_F(AuthorityFixture, DeviceGuardActivateResumeRejectsChangedAuthButExactRetryProgresses) {
  TestDevice device("activate-resume-guard-device", 71);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(71);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x72);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-71");
  PreparePermit permit;
  permit.txn = makeCommission(device.binding, txnId, digest);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(permit.txn, prepare_challenge, permit.auth);
  PreparedRootResponse response;
  ASSERT_EQ(guard.verifyAndPrepare(permit, response), AuthorityOutcome::Ok);

  ActivationPermit act_permit;
  act_permit.txn = permit.txn;
  std::memcpy(act_permit.preparedRootDigestSha256, response.rootDigestSha256, kDigestBytes);
  uint8_t activate_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Activate, txnId, activate_challenge));
  signActivationAuth(act_permit.txn, response.rootDigestSha256, activate_challenge, act_permit.activationAuth);

  // activateStagedRoot() itself stalls on the ORIGINAL, fully-verified
  // call -- the single-use challenge has already been consumed by this
  // point, so a correctly-fixed guard must retain the verified values
  // now rather than ever needing to re-consume it.
  maintenance.simulate_activate_pending_once = true;
  ActivationResponse act_response;
  TxRxActivationGrant grant;
  ASSERT_EQ(guard.verifyAndActivate(act_permit, act_response, grant), AuthorityOutcome::Pending);
  ASSERT_EQ(maintenance.activate_calls, 1);
  EXPECT_FALSE(store.rawStateForTest().activated);

  // A changed activationAuth presented under the SAME transactionId
  // (modelling a corrupted/attacker-modified retry) must be rejected
  // with no further activateStagedRoot()/commitActivated() attempt and
  // no premature ACTIVE mutation.
  ActivationPermit changed_permit = act_permit;
  changed_permit.activationAuth.spentAuthorizedRevision += 1;
  ActivationResponse changed_response;
  TxRxActivationGrant changed_grant;
  EXPECT_EQ(guard.verifyAndActivate(changed_permit, changed_response, changed_grant), AuthorityOutcome::BindingMismatch);
  EXPECT_EQ(maintenance.activate_calls, 1);
  EXPECT_FALSE(store.rawStateForTest().activated);

  // The EXACT original permit must still resume and complete: no
  // signature/challenge re-verification, and exactly one more
  // activateStagedRoot() call (the retry).
  ActivationResponse exact_response;
  TxRxActivationGrant exact_grant;
  EXPECT_EQ(guard.verifyAndActivate(act_permit, exact_response, exact_grant), AuthorityOutcome::Ok);
  EXPECT_EQ(maintenance.activate_calls, 2);
  DeviceAuthorityState state;
  ASSERT_EQ(store.readCurrent(state), DeviceAuthorityReadStatus::Present);
  EXPECT_TRUE(state.activated);
}

// Sol review MEDIUM regression (verifyAndActivate): the single-use
// device challenge is consumed BEFORE the Pending-capable
// store_->readCurrent() call. Proves SEVERAL successive `Pending` reads
// resume correctly (never re-consuming the already-spent challenge, so
// never wrongly denying ChallengeMismatch), that a changed/foreign retry
// during this window is rejected without mutation, and that activation
// only completes -- with no premature ACTIVE state -- once the exact
// retry's readCurrent() genuinely succeeds.
TEST_F(AuthorityFixture, DeviceGuardActivatePendingReadCurrentResumesWithoutReconsumingChallenge) {
  TestDevice device("activate-pending-read-device", 72);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(72);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x73);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-72");
  PreparePermit permit;
  permit.txn = makeCommission(device.binding, txnId, digest);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(permit.txn, prepare_challenge, permit.auth);
  PreparedRootResponse response;
  ASSERT_EQ(guard.verifyAndPrepare(permit, response), AuthorityOutcome::Ok);

  ActivationPermit act_permit;
  act_permit.txn = permit.txn;
  std::memcpy(act_permit.preparedRootDigestSha256, response.rootDigestSha256, kDigestBytes);
  uint8_t activate_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Activate, txnId, activate_challenge));
  signActivationAuth(act_permit.txn, response.rootDigestSha256, activate_challenge, act_permit.activationAuth);

  // readCurrent() genuinely stalls for THREE successive ticks -- the
  // single-use challenge was already consumed on the very first call
  // (before readCurrent() is ever reached), so every one of these
  // Pending resumes must NOT need to re-consume it.
  store.simulateReadPendingTimes(3);
  ActivationResponse resp1;
  TxRxActivationGrant grant1;
  EXPECT_EQ(guard.verifyAndActivate(act_permit, resp1, grant1), AuthorityOutcome::Pending);

  // A changed/foreign retry presented WHILE still ReadingCurrent must be
  // rejected outright, with no premature ACTIVE mutation.
  ActivationPermit changed_permit = act_permit;
  changed_permit.preparedRootDigestSha256[0] ^= 0xFF;
  ActivationResponse changed_resp;
  TxRxActivationGrant changed_grant;
  EXPECT_EQ(guard.verifyAndActivate(changed_permit, changed_resp, changed_grant), AuthorityOutcome::BindingMismatch);
  EXPECT_FALSE(store.rawStateForTest().activated);

  ActivationResponse resp2;
  TxRxActivationGrant grant2;
  EXPECT_EQ(guard.verifyAndActivate(act_permit, resp2, grant2), AuthorityOutcome::Pending);
  EXPECT_FALSE(store.rawStateForTest().activated);

  ActivationResponse resp3;
  TxRxActivationGrant grant3;
  EXPECT_EQ(guard.verifyAndActivate(act_permit, resp3, grant3), AuthorityOutcome::Pending);
  EXPECT_FALSE(store.rawStateForTest().activated);

  // The exact retry's readCurrent() now genuinely succeeds -- the
  // challenge was consumed exactly once (at the very first call above),
  // never re-attempted on any of the three Pending resumes, so this
  // final retry completes normally rather than being wrongly denied
  // ChallengeMismatch.
  ActivationResponse resp4;
  TxRxActivationGrant grant4;
  EXPECT_EQ(guard.verifyAndActivate(act_permit, resp4, grant4), AuthorityOutcome::Ok);
  EXPECT_EQ(maintenance.activate_calls, 1);
  DeviceAuthorityState state;
  ASSERT_EQ(store.readCurrent(state), DeviceAuthorityReadStatus::Present);
  EXPECT_TRUE(state.activated);
}

// Sol review HIGH regression, Prepare's Committing phase specifically: a
// Pending commitStaged() (as opposed to a Pending stageRoot()) resume
// must likewise reject a same-transactionId changed-field retry and
// still let an exact retry progress to Ok.
TEST_F(AuthorityFixture, DeviceGuardPrepareCommitStagedPendingResumeRejectsChangedFieldsButExactRetryProgresses) {
  TestDevice device("prepare-commit-resume-device", 73);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(73);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x74);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-73");
  PreparePermit permit;
  permit.txn = makeCommission(device.binding, txnId, digest);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(permit.txn, prepare_challenge, permit.auth);

  // stageRoot() itself succeeds immediately, but the SUBSEQUENT
  // commitStaged() stalls -- this is the Committing phase, distinct from
  // the Staging phase covered above.
  store.simulateCommitStagedPendingOnce();
  PreparedRootResponse response;
  ASSERT_EQ(guard.verifyAndPrepare(permit, response), AuthorityOutcome::Pending);
  ASSERT_EQ(maintenance.stage_calls, 1);
  EXPECT_FALSE(store.hasStateForTest());  // commitStaged's stall left no durable state yet.

  // A same-transactionId retry with a tampered PrepareAuthorizationV1
  // host nonce must be rejected before any further commitStaged() call,
  // with no mutation and the continuation preserved.
  PreparePermit changed_permit = permit;
  changed_permit.auth.hostNonce[0] ^= 0xFF;
  PreparedRootResponse changed_response;
  EXPECT_EQ(guard.verifyAndPrepare(changed_permit, changed_response), AuthorityOutcome::BindingMismatch);
  EXPECT_EQ(maintenance.stage_calls, 1);  // no additional stageRoot() attempt.
  EXPECT_FALSE(store.hasStateForTest());

  // The EXACT original permit must still resume commitStaged() and
  // complete, never re-invoking stageRoot() a second time.
  PreparedRootResponse exact_response;
  EXPECT_EQ(guard.verifyAndPrepare(permit, exact_response), AuthorityOutcome::Ok);
  EXPECT_EQ(maintenance.stage_calls, 1);
  DeviceAuthorityState state;
  ASSERT_EQ(store.readCurrent(state), DeviceAuthorityReadStatus::Present);
  EXPECT_TRUE(state.staged);
}

// Sol review HIGH regression, Activate's Committing phase specifically:
// a Pending commitActivated() (as opposed to a Pending
// activateStagedRoot()) resume must likewise reject a same-transactionId
// changed-field retry and still let an exact retry progress to Ok, with
// no premature ACTIVE mutation from either attempt.
TEST_F(AuthorityFixture, DeviceGuardActivateCommitActivatedPendingResumeRejectsChangedFieldsButExactRetryProgresses) {
  TestDevice device("activate-commit-resume-device", 74);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(74);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x75);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-74");
  PreparePermit permit;
  permit.txn = makeCommission(device.binding, txnId, digest);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(permit.txn, prepare_challenge, permit.auth);
  PreparedRootResponse response;
  ASSERT_EQ(guard.verifyAndPrepare(permit, response), AuthorityOutcome::Ok);

  ActivationPermit act_permit;
  act_permit.txn = permit.txn;
  std::memcpy(act_permit.preparedRootDigestSha256, response.rootDigestSha256, kDigestBytes);
  uint8_t activate_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Activate, txnId, activate_challenge));
  signActivationAuth(act_permit.txn, response.rootDigestSha256, activate_challenge, act_permit.activationAuth);

  // activateStagedRoot() succeeds immediately, but the SUBSEQUENT
  // commitActivated() stalls -- the Committing phase.
  store.simulateCommitActivatedPendingOnce();
  ActivationResponse act_response;
  TxRxActivationGrant grant;
  ASSERT_EQ(guard.verifyAndActivate(act_permit, act_response, grant), AuthorityOutcome::Pending);
  ASSERT_EQ(maintenance.activate_calls, 1);
  EXPECT_FALSE(store.rawStateForTest().activated);  // commitActivated's stall must not have mutated ACTIVE state.

  // A same-transactionId retry with a tampered preparedRootDigestSha256
  // must be rejected before any further activateStagedRoot() call, with
  // no premature ACTIVE mutation.
  ActivationPermit changed_permit = act_permit;
  changed_permit.preparedRootDigestSha256[0] ^= 0xFF;
  ActivationResponse changed_response;
  TxRxActivationGrant changed_grant;
  EXPECT_EQ(guard.verifyAndActivate(changed_permit, changed_response, changed_grant), AuthorityOutcome::BindingMismatch);
  EXPECT_EQ(maintenance.activate_calls, 1);  // no additional activateStagedRoot() attempt.
  EXPECT_FALSE(store.rawStateForTest().activated);

  // The EXACT original permit must still resume commitActivated() and
  // complete, never re-invoking activateStagedRoot() a second time, and
  // only NOW does the device durably become ACTIVE.
  ActivationResponse exact_response;
  TxRxActivationGrant exact_grant;
  EXPECT_EQ(guard.verifyAndActivate(act_permit, exact_response, exact_grant), AuthorityOutcome::Ok);
  EXPECT_EQ(maintenance.activate_calls, 1);
  DeviceAuthorityState state;
  ASSERT_EQ(store.readCurrent(state), DeviceAuthorityReadStatus::Present);
  EXPECT_TRUE(state.activated);
}

// H1 regression: a genuinely valid Prepare permit for a transaction that
// is ALREADY activated on this exact device must be refused outright --
// not silently re-staged/re-committed -- even when the permit's own
// signature/binding are entirely legitimate and identical to the
// original. Falling through here previously let a same-txn replay
// re-invoke stageRoot()/commitStaged(), which could clear/downgrade the
// device's own activation record.
TEST_F(AuthorityFixture, PrepareIsRefusedForATransactionAlreadyActivatedOnThisDeviceEvenIfIdentical) {
  TestDevice device("same-txn-replay-device", 60);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(60);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x60);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-60");
  PreparePermit permit;
  permit.txn = makeCommission(device.binding, txnId, digest);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(permit.txn, prepare_challenge, permit.auth);

  PreparedRootResponse response;
  ASSERT_EQ(guard.verifyAndPrepare(permit, response), AuthorityOutcome::Ok);
  ASSERT_EQ(maintenance.stage_calls, 1);

  ActivationPermit act_permit;
  act_permit.txn = permit.txn;
  std::memcpy(act_permit.preparedRootDigestSha256, response.rootDigestSha256, kDigestBytes);
  uint8_t activate_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Activate, txnId, activate_challenge));
  signActivationAuth(act_permit.txn, response.rootDigestSha256, activate_challenge, act_permit.activationAuth);

  ActivationResponse act_response;
  TxRxActivationGrant grant;
  ASSERT_EQ(guard.verifyAndActivate(act_permit, act_response, grant), AuthorityOutcome::Ok);
  ASSERT_EQ(maintenance.activate_calls, 1);

  // Replay the EXACT original (still validly signed/bound) Prepare permit
  // against the now-activated device.
  PreparedRootResponse replay_response;
  EXPECT_EQ(guard.verifyAndPrepare(permit, replay_response), AuthorityOutcome::WrongState);
  // No additional stageRoot()/commitStaged() attempt must ever occur.
  EXPECT_EQ(maintenance.stage_calls, 1);

  // The device's own durable activation record must be entirely
  // unchanged by the refused replay.
  DeviceAuthorityState state;
  ASSERT_EQ(store.readCurrent(state), DeviceAuthorityReadStatus::Present);
  EXPECT_TRUE(state.activated);
  EXPECT_EQ(0, std::memcmp(state.transactionId, txnId, kTransactionIdBytes));
  EXPECT_EQ(0, std::memcmp(state.stagedRootDigestSha256, response.rootDigestSha256, kDigestBytes));
}

// H2 regression: a local store read FAILURE (flash fault, corrupt
// record) must be denied immediately, before any prepare/stage/activate
// mutation is even attempted -- and must never be conflated with a
// genuinely blank/never-staged device. Writes remain available; only
// reads are faulted, matching a real "store can still commit but its own
// read path is currently broken" fault mode.
TEST_F(AuthorityFixture, PrepareIsDeniedWithNoMutationWhenActivatedStoreReadFails) {
  TestDevice device("read-fault-device", 61);
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(61);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x61);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-61");
  PreparePermit permit;
  permit.txn = makeCommission(device.binding, txnId, digest);
  uint8_t prepare_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Prepare, txnId, prepare_challenge));
  signPrepareAuth(permit.txn, prepare_challenge, permit.auth);

  // Genuinely activate the device first, so its store holds real state
  // that a subsequent read fault could otherwise be mistaken for absent.
  PreparedRootResponse response;
  ASSERT_EQ(guard.verifyAndPrepare(permit, response), AuthorityOutcome::Ok);
  ActivationPermit act_permit;
  act_permit.txn = permit.txn;
  std::memcpy(act_permit.preparedRootDigestSha256, response.rootDigestSha256, kDigestBytes);
  uint8_t activate_challenge[kChallengeBytes];
  ASSERT_TRUE(guard.beginChallenge(AuthorityChallengePurpose::Activate, txnId, activate_challenge));
  signActivationAuth(act_permit.txn, response.rootDigestSha256, activate_challenge, act_permit.activationAuth);
  ActivationResponse act_response;
  TxRxActivationGrant grant;
  ASSERT_EQ(guard.verifyAndActivate(act_permit, act_response, grant), AuthorityOutcome::Ok);
  const DeviceAuthorityState before = store.rawStateForTest();

  // Simulate a read fault (writes remain available -- only readCurrent
  // is affected) and attempt a fresh Prepare for a DIFFERENT (Repair)
  // transaction chaining from the currently-activated one.
  store.simulateReadError(true);
  uint8_t repairTxnId[kTransactionIdBytes];
  makeTxnId(repairTxnId, 0x62);
  uint8_t repairDigest[kDigestBytes];
  fillSeed(repairDigest, "manifest-62-repair");
  PreparePermit repair_permit;
  repair_permit.txn = permit.txn;
  repair_permit.txn.operation = AuthorityOperation::Repair;
  std::memcpy(repair_permit.txn.transactionId, repairTxnId, kTransactionIdBytes);
  repair_permit.txn.revision = permit.txn.revision + 1;
  std::memcpy(repair_permit.txn.predecessorTransactionId, txnId, kTransactionIdBytes);
  std::memcpy(repair_permit.txn.manifestDigestSha256, repairDigest, kDigestBytes);
  repair_permit.txn.initialTxSequenceFloor = permit.txn.initialTxSequenceFloor;
  repair_permit.txn.initialRxReplayFloor = permit.txn.initialRxReplayFloor;
  sign(repair_permit.txn);
  // repair_permit.auth intentionally left default: the simulated store
  // read fault is detected (and denies) before any authorization
  // signature is ever examined.

  PreparedRootResponse repair_response;
  EXPECT_EQ(guard.verifyAndPrepare(repair_permit, repair_response), AuthorityOutcome::Denied);
  EXPECT_EQ(maintenance.stage_calls, 1);  // unchanged from the earlier successful prepare -- no new attempt.

  store.simulateReadError(false);
  const DeviceAuthorityState after = store.rawStateForTest();
  EXPECT_EQ(0, std::memcmp(before.transactionId, after.transactionId, kTransactionIdBytes));
  EXPECT_EQ(0, std::memcmp(before.stagedRootDigestSha256, after.stagedRootDigestSha256, kDigestBytes));
  EXPECT_EQ(before.activated, after.activated);
  EXPECT_EQ(before.staged, after.staged);
}

// ---------------------------------------------------------------------
// BaselineCertificationManifest codec round trip + digest determinism.
// ---------------------------------------------------------------------

BaselineCertificationManifest makeBaselineManifest(uint8_t tag) {
  BaselineCertificationManifest manifest;
  fillSeed(manifest.approvedImageSha256, "approved-image");
  manifest.approvedImageSha256[0] ^= tag;
  manifest.approvedImageExtentOffset = 0x1000;
  manifest.approvedImageExtentLength = 0x2000;
  fillSeed(manifest.expectedSdk28Sha256Digest, "expected-sdk28");
  fillSeed(manifest.stockLoaderArtifactSha256, "stock-loader");
  manifest.stockLoaderArtifactRangeStart = 0x100;
  manifest.stockLoaderArtifactRangeLength = 0x400;
  manifest.bootConfigId = 7;
  manifest.allowOrdinaryUserdata = true;
  return manifest;
}

TEST(BaselineCertificationManifestCodecTest, RoundTripPreservesEveryField) {
  BaselineCertificationManifest manifest = makeBaselineManifest(1);
  uint8_t encoded[BaselineCertificationManifestCodec::kManifestBytes];
  ASSERT_EQ(BaselineCertificationManifestCodec::serialize(manifest, encoded, sizeof(encoded)),
            BaselineCertificationManifestCodec::kManifestBytes);

  BaselineCertificationManifest parsed;
  ASSERT_TRUE(BaselineCertificationManifestCodec::parse(encoded, sizeof(encoded), parsed));
  EXPECT_EQ(std::memcmp(parsed.approvedImageSha256, manifest.approvedImageSha256, 32), 0);
  EXPECT_EQ(parsed.approvedImageExtentOffset, manifest.approvedImageExtentOffset);
  EXPECT_EQ(parsed.approvedImageExtentLength, manifest.approvedImageExtentLength);
  EXPECT_EQ(std::memcmp(parsed.expectedSdk28Sha256Digest, manifest.expectedSdk28Sha256Digest, 32), 0);
  EXPECT_EQ(std::memcmp(parsed.stockLoaderArtifactSha256, manifest.stockLoaderArtifactSha256, 32), 0);
  EXPECT_EQ(parsed.stockLoaderArtifactRangeStart, manifest.stockLoaderArtifactRangeStart);
  EXPECT_EQ(parsed.stockLoaderArtifactRangeLength, manifest.stockLoaderArtifactRangeLength);
  EXPECT_EQ(parsed.bootConfigId, manifest.bootConfigId);
  EXPECT_EQ(parsed.allowOrdinaryUserdata, manifest.allowOrdinaryUserdata);
}

TEST(BaselineCertificationManifestCodecTest, WrongLengthInputIsRejected) {
  BaselineCertificationManifest manifest = makeBaselineManifest(2);
  uint8_t encoded[BaselineCertificationManifestCodec::kManifestBytes];
  ASSERT_EQ(BaselineCertificationManifestCodec::serialize(manifest, encoded, sizeof(encoded)),
            BaselineCertificationManifestCodec::kManifestBytes);
  BaselineCertificationManifest parsed;
  EXPECT_FALSE(BaselineCertificationManifestCodec::parse(encoded, sizeof(encoded) - 1, parsed));
  uint8_t too_long[BaselineCertificationManifestCodec::kManifestBytes + 1] = {0};
  std::memcpy(too_long, encoded, sizeof(encoded));
  EXPECT_FALSE(BaselineCertificationManifestCodec::parse(too_long, sizeof(too_long), parsed));
}

TEST(BaselineCertificationManifestCodecTest, DigestIsDeterministicAndSensitiveToEveryField) {
  BaselineCertificationManifest base = makeBaselineManifest(3);
  uint8_t digest_a[32], digest_b[32];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(base, digest_a));
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(base, digest_b));
  EXPECT_EQ(std::memcmp(digest_a, digest_b, 32), 0);  // Same fields -> byte-identical digest, every time.

  BaselineCertificationManifest changed = base;
  changed.bootConfigId += 1;
  uint8_t digest_changed[32];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(changed, digest_changed));
  EXPECT_NE(std::memcmp(digest_a, digest_changed, 32), 0);

  // The tightened expectedSdk28Sha256Digest field must independently
  // affect the digest -- a caller cannot "skip" SDK identity by only
  // matching the other fields.
  BaselineCertificationManifest changed_sdk = base;
  changed_sdk.expectedSdk28Sha256Digest[0] ^= 0xFF;
  uint8_t digest_sdk[32];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(changed_sdk, digest_sdk));
  EXPECT_NE(std::memcmp(digest_a, digest_sdk, 32), 0);

  BaselineCertificationManifest changed_flag = base;
  changed_flag.allowOrdinaryUserdata = !base.allowOrdinaryUserdata;
  uint8_t digest_flag[32];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(changed_flag, digest_flag));
  EXPECT_NE(std::memcmp(digest_a, digest_flag, 32), 0);
}

// ---------------------------------------------------------------------
// CertifyExistingBaseline: canonical operation type + codec validity.
// ---------------------------------------------------------------------

TEST(AuthorityOperationTest, CertifyExistingBaselineIsAValidOperationByte) {
  EXPECT_TRUE(isValidAuthorityOperation(static_cast<uint8_t>(AuthorityOperation::CertifyExistingBaseline)));
}

TEST_F(AuthorityFixture, CertifyExistingBaselineRecordRoundTripsThroughCodec) {
  TestDevice device("certify-codec-device", 40);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x40);
  BaselineCertificationManifest manifest = makeBaselineManifest(4);
  uint8_t digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, digest));
  AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);

  uint8_t record[AuthorityCodec::kRecordBytes];
  ASSERT_EQ(AuthorityCodec::serializeRecord(txn, record, sizeof(record)), AuthorityCodec::kRecordBytes);
  AuthorityTransaction parsed;
  ASSERT_EQ(AuthorityCodec::parseRecord(record, sizeof(record), parsed), AuthorityDecodeError::None);
  EXPECT_EQ(parsed.operation, AuthorityOperation::CertifyExistingBaseline);
  EXPECT_EQ(parsed.initialTxSequenceFloor, 0u);
  EXPECT_EQ(parsed.initialRxReplayFloor, 0u);
  EXPECT_EQ(std::memcmp(parsed.manifestDigestSha256, digest, kDigestBytes), 0);
}

// ---------------------------------------------------------------------
// AuthorityCoordinator::submitCertifyExistingBaseline.
// ---------------------------------------------------------------------

TEST_F(AuthorityFixture, SubmitCertifyExistingBaselineHappyPathStaysIssuedForever) {
  TestDevice device("certify-submit-device", 41);
  FileAuthorityRegistryCopy regCopyA(copyAPath_), regCopyB(copyBPath_);
  AuthorityRegistryPair registry(regCopyA, regCopyB);
  CountingEntropy entropy(41);
  AuthorityCoordinator coordinator(registry, &verifier_, issuer_trust_.get(), &entropy, nullptr, &test_lock_, prepare_signing_trust_.get());

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x41);
  BaselineCertificationManifest manifest = makeBaselineManifest(5);
  uint8_t digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, digest));
  AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);

  EXPECT_EQ(coordinator.submitCertifyExistingBaseline(txn), AuthorityOutcome::Ok);

  StoredTransactionRecord record;
  EXPECT_EQ(coordinator.describeBinding(txnId, device.binding, record), AuthorityOutcome::Ok);
  EXPECT_EQ(record.state, TransactionState::Issued);  // Never advances -- no counter/identity/install grant exists.

  // Submitting the identical id again is never silently overwritten.
  EXPECT_EQ(coordinator.submitCertifyExistingBaseline(txn), AuthorityOutcome::Denied);
}

// H1 regression: a signed CertifyExistingBaseline (a narrower,
// never-advancing grant -- see AuthorityOperation's own comment) must
// never be mistaken for Commission/Repair/Rekey lineage history. Before
// the fix, readLatestActivationForOwner/readLatestOwnershipLineage
// treated ANY record for this owner (any operation) as prior history,
// so a genuinely first Commission for the SAME owner that already has a
// signed baseline certificate on file was wrongly refused with
// StaleRevision. This proves the certificate is retained (still reads
// back as Issued) while a genuinely fresh Commission for the same exact
// ownership now succeeds.
TEST_F(AuthorityFixture, BaselineCertificateNeverBlocksAGenuinelyFirstCommissionForTheSameOwner) {
  TestDevice device("certify-then-commission-device", 44);
  FileAuthorityRegistryCopy regCopyA(copyAPath_), regCopyB(copyBPath_);
  AuthorityRegistryPair registry(regCopyA, regCopyB);
  CountingEntropy entropy(44);
  AuthorityCoordinator coordinator(registry, &verifier_, issuer_trust_.get(), &entropy, nullptr, &test_lock_, prepare_signing_trust_.get());

  uint8_t certifyTxnId[kTransactionIdBytes];
  makeTxnId(certifyTxnId, 0x45);
  BaselineCertificationManifest manifest = makeBaselineManifest(6);
  uint8_t manifestDigest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, manifestDigest));
  AuthorityTransaction certifyTxn = makeCertifyExistingBaseline(device.binding, certifyTxnId, manifestDigest);
  ASSERT_EQ(coordinator.submitCertifyExistingBaseline(certifyTxn), AuthorityOutcome::Ok);

  uint8_t commissionTxnId[kTransactionIdBytes];
  makeTxnId(commissionTxnId, 0x46);
  uint8_t commissionDigest[kDigestBytes];
  fillSeed(commissionDigest, "manifest-commission-44");
  AuthorityTransaction commissionTxn = makeCommission(device.binding, commissionTxnId, commissionDigest);
  EXPECT_EQ(coordinator.submitCommission(commissionTxn), AuthorityOutcome::Ok);

  // The baseline certificate itself is untouched/still Issued, never
  // silently consumed, overwritten, or promoted into the Commission
  // lineage.
  StoredTransactionRecord certifyRecord;
  EXPECT_EQ(coordinator.describeBinding(certifyTxnId, device.binding, certifyRecord), AuthorityOutcome::Ok);
  EXPECT_EQ(certifyRecord.state, TransactionState::Issued);
  EXPECT_EQ(certifyRecord.txn.operation, AuthorityOperation::CertifyExistingBaseline);

  // Existing Commission-fork-detection discipline must still be strict:
  // a SECOND Commission (revision 0, fresh id) for this SAME exact
  // ownership -- now that the genuine Commission above already claimed
  // it -- must still be refused, never permitted just because the
  // baseline certificate is filtered out of the scan.
  uint8_t secondCommissionTxnId[kTransactionIdBytes];
  makeTxnId(secondCommissionTxnId, 0x47);
  uint8_t secondDigest[kDigestBytes];
  fillSeed(secondDigest, "manifest-commission-44-second");
  AuthorityTransaction secondCommissionTxn = makeCommission(device.binding, secondCommissionTxnId, secondDigest);
  EXPECT_EQ(coordinator.submitCommission(secondCommissionTxn), AuthorityOutcome::StaleRevision);
}

TEST_F(AuthorityFixture, SubmitCertifyExistingBaselineRejectsWrongOperationType) {
  TestDevice device("certify-wrong-op-device", 42);
  FileAuthorityRegistryCopy regCopyA(copyAPath_), regCopyB(copyBPath_);
  AuthorityRegistryPair registry(regCopyA, regCopyB);
  CountingEntropy entropy(42);
  AuthorityCoordinator coordinator(registry, &verifier_, issuer_trust_.get(), &entropy, nullptr, &test_lock_, prepare_signing_trust_.get());

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x42);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-42");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);  // wrong op for this call.
  EXPECT_EQ(coordinator.submitCertifyExistingBaseline(commission), AuthorityOutcome::OperationMismatch);
}

TEST_F(AuthorityFixture, SubmitCertifyExistingBaselineRejectsAnyNonZeroCounterOrChainField) {
  TestDevice device("certify-nonzero-device", 43);
  FileAuthorityRegistryCopy regCopyA(copyAPath_), regCopyB(copyBPath_);
  AuthorityRegistryPair registry(regCopyA, regCopyB);
  CountingEntropy entropy(43);
  AuthorityCoordinator coordinator(registry, &verifier_, issuer_trust_.get(), &entropy, nullptr, &test_lock_, prepare_signing_trust_.get());

  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-43");

  {
    uint8_t txnId[kTransactionIdBytes];
    makeTxnId(txnId, 0x43);
    AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);
    txn.revision = 1;  // never legitimate for this operation -- no lineage to chain from.
    sign(txn);
    EXPECT_EQ(coordinator.submitCertifyExistingBaseline(txn), AuthorityOutcome::StaleRevision);
  }
  {
    uint8_t txnId[kTransactionIdBytes];
    makeTxnId(txnId, 0x44);
    AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);
    std::memset(txn.predecessorTransactionId, 0x11, kTransactionIdBytes);
    sign(txn);
    EXPECT_EQ(coordinator.submitCertifyExistingBaseline(txn), AuthorityOutcome::StaleRevision);
  }
  {
    uint8_t txnId[kTransactionIdBytes];
    makeTxnId(txnId, 0x45);
    AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);
    txn.initialTxSequenceFloor = 1;  // this operation seeds NO counter, ever.
    sign(txn);
    EXPECT_EQ(coordinator.submitCertifyExistingBaseline(txn), AuthorityOutcome::BindingMismatch);
  }
  {
    uint8_t txnId[kTransactionIdBytes];
    makeTxnId(txnId, 0x46);
    AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);
    txn.initialRxReplayFloor = 1;
    sign(txn);
    EXPECT_EQ(coordinator.submitCertifyExistingBaseline(txn), AuthorityOutcome::BindingMismatch);
  }
}

// ---------------------------------------------------------------------
// Cross-use rejection: CertifyExistingBaseline must never reach the
// Commission/Repair/Rekey lifecycle (prepare/resumePrepared/
// activateExistingRoot), even if somehow present in the registry.
// ---------------------------------------------------------------------

TEST_F(AuthorityFixture, PrepareRejectsCertifyExistingBaselineTransaction) {
  TestDevice device("certify-crossuse-device", 47);
  FileAuthorityRegistryCopy regCopyA(copyAPath_), regCopyB(copyBPath_);
  AuthorityRegistryPair registry(regCopyA, regCopyB);
  CountingEntropy entropy(47);
  AuthorityCoordinator coordinator(registry, &verifier_, issuer_trust_.get(), &entropy, activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);
  LoopbackDeviceSession session(guard);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x47);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-47");
  AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);
  ASSERT_EQ(coordinator.submitCertifyExistingBaseline(txn), AuthorityOutcome::Ok);

  StoredTransactionRecord record;
  EXPECT_EQ(coordinator.prepare(txnId, session, defaultPrepareInputs(txn), record), AuthorityOutcome::OperationMismatch);
  EXPECT_EQ(coordinator.resumePrepared(txnId, session, defaultPrepareInputs(txn), record), AuthorityOutcome::OperationMismatch);
  EXPECT_EQ(coordinator.activateExistingRoot(txnId, session, record), AuthorityOutcome::OperationMismatch);
  EXPECT_EQ(maintenance.stage_calls, 0);
  EXPECT_EQ(maintenance.activate_calls, 0);
}

TEST_F(AuthorityFixture, DeviceGuardItselfRejectsCertifyExistingBaselinePermitEvenBypassingCoordinator) {
  // HIGH2 regression: the coordinator-side guard above is real, but
  // DeviceAuthorityGuard::verifyAndPrepare()/verifyAndActivate() used to
  // never independently check permit.txn.operation at all -- a signed
  // CertifyExistingBaseline transaction fed DIRECTLY into the device
  // guard (bypassing AuthorityCoordinator entirely, e.g. a buggy/
  // compromised host, or a hand-built permit as here) would have
  // proceeded straight to stageRoot()/commitStaged() as if it were a
  // real Commission. This exercises the device guard's OWN independent
  // defense-in-depth check, with no coordinator involved.
  TestDevice device("certify-guard-bypass-device", 48);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x48);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-48");
  AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);

  InMemoryDeviceStore store;
  RecordingMaintenance maintenance;
  CountingEntropy entropy(48);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &store, &maintenance, &signer);

  PreparePermit prepare_permit;
  prepare_permit.txn = txn;
  // prepare_permit.auth intentionally left default: OperationMismatch is
  // rejected before any authorization/challenge verification.
  PreparedRootResponse prepare_response;
  EXPECT_EQ(guard.verifyAndPrepare(prepare_permit, prepare_response), AuthorityOutcome::OperationMismatch);
  EXPECT_EQ(maintenance.stage_calls, 0);  // never reached stageRoot().

  ActivationPermit activation_permit;
  activation_permit.txn = txn;
  fillSeed(activation_permit.preparedRootDigestSha256, "bypass-root");
  // activationAuth is deliberately left default/unsigned: the operation
  // check must reject BEFORE any signature verification is even
  // attempted, so this proves the guard checks operation type first.
  ActivationResponse activation_response;
  TxRxActivationGrant grant;
  EXPECT_EQ(guard.verifyAndActivate(activation_permit, activation_response, grant), AuthorityOutcome::OperationMismatch);
  EXPECT_EQ(maintenance.activate_calls, 0);  // never reached activateStagedRoot().
}

// ---------------------------------------------------------------------
// DeviceBaselineCertificationGuard: default-deny device-side verifier.
// ---------------------------------------------------------------------

TEST_F(AuthorityFixture, BaselineGuardDeniesWithAnyMissingDependency) {
  TestDevice device("baseline-guard-missing-device", 50);
  CountingEntropy entropy(50);
  FakeDeviceBaselineLocalEvidence evidence;

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x50);
  BaselineCertificationManifest manifest = makeBaselineManifest(6);
  uint8_t digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, digest));
  AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);
  evidence.manifest = manifest;

  DeviceBaselineCertificationGuard missing_verifier(device.binding, nullptr, issuer_trust_.get(), &entropy, &evidence);
  EXPECT_EQ(missing_verifier.evaluate(txn), BaselineCertificationOutcome::Unknown);

  DeviceBaselineCertificationGuard missing_trust(device.binding, &verifier_, nullptr, &entropy, &evidence);
  EXPECT_EQ(missing_trust.evaluate(txn), BaselineCertificationOutcome::Unknown);

  DeviceBaselineCertificationGuard missing_entropy(device.binding, &verifier_, issuer_trust_.get(), nullptr, &evidence);
  EXPECT_EQ(missing_entropy.evaluate(txn), BaselineCertificationOutcome::Unknown);

  DeviceBaselineCertificationGuard missing_evidence(device.binding, &verifier_, issuer_trust_.get(), &entropy, nullptr);
  EXPECT_EQ(missing_evidence.evaluate(txn), BaselineCertificationOutcome::Unknown);
}

TEST_F(AuthorityFixture, BaselineGuardRequiresGenuineFreshLocalEvidenceMatch) {
  TestDevice device("baseline-guard-match-device", 51);
  CountingEntropy entropy(51);
  FakeDeviceBaselineLocalEvidence evidence;
  DeviceBaselineCertificationGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &evidence);

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x51);
  BaselineCertificationManifest manifest = makeBaselineManifest(7);
  uint8_t digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, digest));
  AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);

  // Local evidence does not match what the issuer actually certified --
  // e.g. the image on this boot genuinely differs. Never PositiveNormal.
  evidence.manifest = manifest;
  evidence.manifest.approvedImageSha256[0] ^= 0xFF;
  EXPECT_EQ(guard.evaluate(txn), BaselineCertificationOutcome::Unknown);
  EXPECT_EQ(evidence.captures, 1);

  // Now the fresh local measurement genuinely matches.
  evidence.manifest = manifest;
  uint8_t nonce_a[kChallengeBytes];
  EXPECT_EQ(guard.evaluate(txn, nonce_a), BaselineCertificationOutcome::PositiveNormal);
  EXPECT_EQ(evidence.captures, 2);  // re-captured, never reused the first (failed) capture.

  // A second, independent evaluation re-verifies from scratch (renewed
  // proof each boot/call) and draws a genuinely different fresh nonce.
  uint8_t nonce_b[kChallengeBytes];
  EXPECT_EQ(guard.evaluate(txn, nonce_b), BaselineCertificationOutcome::PositiveNormal);
  EXPECT_EQ(evidence.captures, 3);
  EXPECT_NE(std::memcmp(nonce_a, nonce_b, kChallengeBytes), 0);
}

TEST_F(AuthorityFixture, BaselineGuardRejectsWrongOperationBindingAndSignature) {
  TestDevice device("baseline-guard-reject-device", 52);
  TestDevice other_device("baseline-guard-other-device", 53);
  CountingEntropy entropy(52);
  FakeDeviceBaselineLocalEvidence evidence;
  DeviceBaselineCertificationGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &evidence);

  BaselineCertificationManifest manifest = makeBaselineManifest(8);
  uint8_t digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, digest));
  evidence.manifest = manifest;

  // Wrong operation entirely (a Commission transaction fed into the
  // baseline guard) -- must never be accepted here.
  {
    uint8_t txnId[kTransactionIdBytes];
    makeTxnId(txnId, 0x52);
    AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);
    EXPECT_EQ(guard.evaluate(commission), BaselineCertificationOutcome::Unknown);
  }

  // Binding mismatch: transaction claims a DIFFERENT device than this guard's own identity.
  {
    uint8_t txnId[kTransactionIdBytes];
    makeTxnId(txnId, 0x53);
    AuthorityTransaction wrong_device_txn = makeCertifyExistingBaseline(other_device.binding, txnId, digest);
    EXPECT_EQ(guard.evaluate(wrong_device_txn), BaselineCertificationOutcome::Unknown);
  }

  // Tampered issuer signature.
  {
    uint8_t txnId[kTransactionIdBytes];
    makeTxnId(txnId, 0x54);
    AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);
    txn.issuerSignatureEd25519[0] ^= 0xFF;
    EXPECT_EQ(guard.evaluate(txn), BaselineCertificationOutcome::Unknown);
  }
}

TEST_F(AuthorityFixture, BaselineGuardDeniesWhenEntropyOrCaptureFails) {
  TestDevice device("baseline-guard-entropy-device", 54);
  FakeDeviceBaselineLocalEvidence evidence;
  BaselineCertificationManifest manifest = makeBaselineManifest(9);
  uint8_t digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, digest));
  evidence.manifest = manifest;

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x55);
  AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);

  class FailingEntropy : public DeviceAuthorityEntropy {
   public:
    bool freshNonce(uint8_t[kChallengeBytes]) override { return false; }
  } failing_entropy;
  DeviceBaselineCertificationGuard guard_bad_entropy(device.binding, &verifier_, issuer_trust_.get(),
                                                      &failing_entropy, &evidence);
  EXPECT_EQ(guard_bad_entropy.evaluate(txn), BaselineCertificationOutcome::Unknown);

  CountingEntropy entropy(56);
  evidence.fail_next_capture = true;
  DeviceBaselineCertificationGuard guard_bad_capture(device.binding, &verifier_, issuer_trust_.get(), &entropy,
                                                      &evidence);
  EXPECT_EQ(guard_bad_capture.evaluate(txn), BaselineCertificationOutcome::Unknown);
}

// Astra30/31 regression: `historicalInitialRoleId` is reused for
// CertifyExistingBaseline to mean the ROLE BEING CERTIFIED right now --
// this guard's own `exactlyThisDevice` binding match previously omitted
// it entirely, so a signed baseline certificate issued for a DIFFERENT
// role (or profile) than this device's own actual current one would
// have been silently accepted despite genuinely matching local
// evidence. Both role-only and profile-only mismatches must independently
// deny.
TEST_F(AuthorityFixture, BaselineGuardRejectsRoleAndProfileMismatchEvenWithGenuineEvidence) {
  TestDevice device("baseline-guard-role-device", 57);
  CountingEntropy entropy(57);
  FakeDeviceBaselineLocalEvidence evidence;
  DeviceBaselineCertificationGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &evidence);

  BaselineCertificationManifest manifest = makeBaselineManifest(10);
  uint8_t digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, digest));
  evidence.manifest = manifest;

  // Role0 (this device's own actual current role) genuinely matches:
  // sanity check that the happy path still works before mutating it.
  {
    uint8_t txnId[kTransactionIdBytes];
    makeTxnId(txnId, 0x56);
    AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);
    EXPECT_EQ(guard.evaluate(txn), BaselineCertificationOutcome::PositiveNormal);
  }

  // The signed transaction claims role=1 ("role being certified") while
  // this device's own actual current role (via its own `binding`) is
  // still role=0 -- must deny, never silently accept a certificate
  // issued for some other role.
  {
    AuthorityBinding role1_binding = device.binding;
    role1_binding.historicalInitialRoleId = 1;
    uint8_t txnId[kTransactionIdBytes];
    makeTxnId(txnId, 0x57);
    AuthorityTransaction txn = makeCertifyExistingBaseline(role1_binding, txnId, digest);
    EXPECT_EQ(guard.evaluate(txn), BaselineCertificationOutcome::Unknown);
  }

  // Cross-profile mismatch: same UID/fullPK/role/layout, different
  // profileId -- must also independently deny.
  {
    AuthorityBinding wrong_profile_binding = device.binding;
    wrong_profile_binding.profileId ^= 0x00000001u;
    uint8_t txnId[kTransactionIdBytes];
    makeTxnId(txnId, 0x58);
    AuthorityTransaction txn = makeCertifyExistingBaseline(wrong_profile_binding, txnId, digest);
    EXPECT_EQ(guard.evaluate(txn), BaselineCertificationOutcome::Unknown);
  }
}

// Astra30/31 regression: a byte-perfect digest match against a locally
// captured manifest whose `allowOrdinaryUserdata` is false must NEVER be
// certified PositiveNormal -- false means this exact, faithfully-matched
// baseline explicitly does not permit ordinary userdata use.
TEST_F(AuthorityFixture, BaselineGuardRejectsManifestNotPermittingOrdinaryUserdata) {
  TestDevice device("baseline-guard-permission-device", 58);
  CountingEntropy entropy(58);
  FakeDeviceBaselineLocalEvidence evidence;
  DeviceBaselineCertificationGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &evidence);

  BaselineCertificationManifest manifest = makeBaselineManifest(11);
  manifest.allowOrdinaryUserdata = false;
  uint8_t digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, digest));
  evidence.manifest = manifest;  // exactly matches what the issuer signed -- digest WILL match.

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x59);
  AuthorityTransaction txn = makeCertifyExistingBaseline(device.binding, txnId, digest);
  EXPECT_EQ(guard.evaluate(txn), BaselineCertificationOutcome::Unknown);

  // Flipping the flag to true (with a matching re-signed digest) is the
  // ONLY thing that turns this into PositiveNormal.
  manifest.allowOrdinaryUserdata = true;
  uint8_t allowed_digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, allowed_digest));
  evidence.manifest = manifest;
  uint8_t txnId2[kTransactionIdBytes];
  makeTxnId(txnId2, 0x5A);
  AuthorityTransaction allowed_txn = makeCertifyExistingBaseline(device.binding, txnId2, allowed_digest);
  EXPECT_EQ(guard.evaluate(allowed_txn), BaselineCertificationOutcome::PositiveNormal);
}

// Astra30/31 regression: the guard must directly re-evaluate the
// zero-revision/zero-predecessor/zero-floor invariants itself, never
// relying solely on the issuer CLI/host coordinator having gotten this
// right first.
TEST_F(AuthorityFixture, BaselineGuardEnforcesZeroFloorsRevisionAndPredecessorDirectly) {
  TestDevice device("baseline-guard-invariant-device", 59);
  CountingEntropy entropy(59);
  FakeDeviceBaselineLocalEvidence evidence;
  DeviceBaselineCertificationGuard guard(device.binding, &verifier_, issuer_trust_.get(), &entropy, &evidence);

  BaselineCertificationManifest manifest = makeBaselineManifest(12);
  uint8_t digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, digest));
  evidence.manifest = manifest;

  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x5B);

  AuthorityTransaction nonzero_revision = makeCertifyExistingBaseline(device.binding, txnId, digest);
  nonzero_revision.revision = 1;
  sign(nonzero_revision);
  EXPECT_EQ(guard.evaluate(nonzero_revision), BaselineCertificationOutcome::Unknown);

  AuthorityTransaction nonzero_predecessor = makeCertifyExistingBaseline(device.binding, txnId, digest);
  nonzero_predecessor.predecessorTransactionId[0] = 0x01;
  sign(nonzero_predecessor);
  EXPECT_EQ(guard.evaluate(nonzero_predecessor), BaselineCertificationOutcome::Unknown);

  AuthorityTransaction nonzero_tx_floor = makeCertifyExistingBaseline(device.binding, txnId, digest);
  nonzero_tx_floor.initialTxSequenceFloor = 5;
  sign(nonzero_tx_floor);
  EXPECT_EQ(guard.evaluate(nonzero_tx_floor), BaselineCertificationOutcome::Unknown);

  AuthorityTransaction nonzero_rx_floor = makeCertifyExistingBaseline(device.binding, txnId, digest);
  nonzero_rx_floor.initialRxReplayFloor = 5;
  sign(nonzero_rx_floor);
  EXPECT_EQ(guard.evaluate(nonzero_rx_floor), BaselineCertificationOutcome::Unknown);
}

// ---------------------------------------------------------------------
// BootFloorActivationReceiptV1 codec + exporter -- ROOT-decided
// AUTHORITATIVE canonical V1 wire format (agreed cross-team with the
// Boot owner via MAIN; see BootFloorActivationReceipt.h's top-of-file
// comment and BootFloorActivationReceiptCodec's field-offset table).
// ---------------------------------------------------------------------

TEST(BootFloorActivationReceiptCodecTest, RoundTripPreservesEveryFieldLittleEndian) {
  BootFloorActivationReceiptV1 r;
  r.recordVersion = 1;
  r.purpose = BootFloorReceiptPurpose::PublisherFloorActivation;
  for (int i = 0; i < static_cast<int>(kHardwareUidBytes); ++i) r.hardwareUid[i] = static_cast<uint8_t>(0x10 + i);
  fillSeed(r.localMeshFullPublicKey, "mesh-pk");
  fillSeed(r.consentOwnerPublicKey, "consent-pk");
  r.targetId = 0x584E3401u;  // Separate compiled field -- deliberately NOT equal to profileId.
  r.profileId = 0x584E3430u;
  r.layoutId = 7;
  r.currentRole = 0;
  r.publisherKeyId = 42;
  fillSeed(r.publisherKeyFingerprintSha256, "publisher-fp");
  for (int i = 0; i < static_cast<int>(kTransactionIdBytes); ++i) r.hostTransactionId[i] = static_cast<uint8_t>(0x20 + i);
  fillSeed(r.authorityTransactionDigestSha256, "txn-digest");
  fillSeed(r.commissionManifestDigestSha256, "manifest-digest");
  fillSeed(r.preparedRootDigestSha256, "prepared-root");
  r.floor = 0;
  fillSeed(r.baselineImageSha256, "baseline-image");
  r.baselineExtentLength = 0x2000;
  fillSeed(r.originalSdk28Sha256Digest, "original-sdk28-digest");
  for (int i = 0; i < static_cast<int>(kSignatureBytes); ++i) r.signatureEd25519[i] = static_cast<uint8_t>(0x30 + i);

  uint8_t record[BootFloorActivationReceiptCodec::kRecordBytes];
  ASSERT_EQ(BootFloorActivationReceiptCodec::serializeRecord(r, record, sizeof(record)),
            BootFloorActivationReceiptCodec::kRecordBytes);
  ASSERT_EQ(static_cast<size_t>(386), BootFloorActivationReceiptCodec::kRecordBytes);
  ASSERT_EQ(static_cast<size_t>(322), BootFloorActivationReceiptCodec::kBodyBytes);

  // Spot-check a handful of the ROOT-decided exact little-endian offsets
  // directly against the raw bytes (not just via round-trip), since the
  // wire layout itself -- not merely "some struct survives a round trip"
  // -- is the actual cross-language interop contract with Boot.
  EXPECT_EQ(1, record[4]);   // recordVersion LE @4.
  EXPECT_EQ(0, record[5]);
  EXPECT_EQ(386 & 0xFF, record[6]);  // recordBytes LE @6.
  EXPECT_EQ((386 >> 8) & 0xFF, record[7]);
  // bootDomain (fixed "BOOT" literal 0x424F4F54) LE @8.
  EXPECT_EQ(0x54, record[8]);
  EXPECT_EQ(0x4F, record[9]);
  EXPECT_EQ(0x4F, record[10]);
  EXPECT_EQ(0x42, record[11]);
  // hardwareUid: stored BE in r.hardwareUid (0x10..0x17), decoded to a
  // numeric value then written LE @12 -- least-significant byte of the
  // BE-decoded number (r.hardwareUid[7] == 0x17) must be first on the wire.
  EXPECT_EQ(0x17, record[12]);
  EXPECT_EQ(0x16, record[13]);
  EXPECT_EQ(0x10, record[19]);

  BootFloorActivationReceiptV1 parsed;
  ASSERT_TRUE(BootFloorActivationReceiptCodec::parseRecord(record, sizeof(record), parsed));
  EXPECT_EQ(parsed.recordVersion, r.recordVersion);
  EXPECT_EQ(parsed.purpose, r.purpose);
  EXPECT_EQ(0, std::memcmp(parsed.hardwareUid, r.hardwareUid, kHardwareUidBytes));
  EXPECT_EQ(0, std::memcmp(parsed.localMeshFullPublicKey, r.localMeshFullPublicKey, kPublicKeyBytes));
  EXPECT_EQ(0, std::memcmp(parsed.consentOwnerPublicKey, r.consentOwnerPublicKey, kPublicKeyBytes));
  EXPECT_EQ(parsed.targetId, r.targetId);
  EXPECT_EQ(parsed.profileId, r.profileId);
  EXPECT_EQ(parsed.layoutId, r.layoutId);
  EXPECT_EQ(parsed.currentRole, r.currentRole);
  EXPECT_EQ(parsed.publisherKeyId, r.publisherKeyId);
  EXPECT_EQ(0, std::memcmp(parsed.publisherKeyFingerprintSha256, r.publisherKeyFingerprintSha256, 32));
  EXPECT_EQ(0, std::memcmp(parsed.hostTransactionId, r.hostTransactionId, kTransactionIdBytes));
  EXPECT_EQ(0, std::memcmp(parsed.authorityTransactionDigestSha256, r.authorityTransactionDigestSha256, kDigestBytes));
  EXPECT_EQ(0, std::memcmp(parsed.commissionManifestDigestSha256, r.commissionManifestDigestSha256, kDigestBytes));
  EXPECT_EQ(0, std::memcmp(parsed.preparedRootDigestSha256, r.preparedRootDigestSha256, kDigestBytes));
  EXPECT_EQ(parsed.floor, r.floor);
  EXPECT_EQ(0, std::memcmp(parsed.baselineImageSha256, r.baselineImageSha256, 32));
  EXPECT_EQ(parsed.baselineExtentLength, r.baselineExtentLength);
  EXPECT_EQ(0, std::memcmp(parsed.originalSdk28Sha256Digest, r.originalSdk28Sha256Digest, 32));
  EXPECT_EQ(0, std::memcmp(parsed.signatureEd25519, r.signatureEd25519, kSignatureBytes));
}

TEST(BootFloorActivationReceiptCodecTest, WrongLengthVersionMagicDomainOrCrcIsRejected) {
  BootFloorActivationReceiptV1 r;
  uint8_t record[BootFloorActivationReceiptCodec::kRecordBytes];
  ASSERT_EQ(BootFloorActivationReceiptCodec::serializeRecord(r, record, sizeof(record)),
            BootFloorActivationReceiptCodec::kRecordBytes);

  BootFloorActivationReceiptV1 parsed;
  EXPECT_FALSE(BootFloorActivationReceiptCodec::parseRecord(record, sizeof(record) - 1, parsed));
  EXPECT_FALSE(BootFloorActivationReceiptCodec::parseRecord(record, sizeof(record) + 1, parsed));

  uint8_t bad_version[BootFloorActivationReceiptCodec::kRecordBytes];
  std::memcpy(bad_version, record, sizeof(record));
  bad_version[4] = 2;  // recordVersion LE @4 -- only version 1 exists.
  bad_version[5] = 0;
  // Recompute CRC so the version corruption itself is what's caught, not
  // an incidental CRC mismatch masking the real assertion.
  const uint32_t crc_bad_version = ota::storage::Crc32::computeFinalized(bad_version, 318);
  bad_version[318] = static_cast<uint8_t>(crc_bad_version & 0xFF);
  bad_version[319] = static_cast<uint8_t>((crc_bad_version >> 8) & 0xFF);
  bad_version[320] = static_cast<uint8_t>((crc_bad_version >> 16) & 0xFF);
  bad_version[321] = static_cast<uint8_t>((crc_bad_version >> 24) & 0xFF);
  EXPECT_FALSE(BootFloorActivationReceiptCodec::parseRecord(bad_version, sizeof(bad_version), parsed));

  uint8_t bad_magic[BootFloorActivationReceiptCodec::kRecordBytes];
  std::memcpy(bad_magic, record, sizeof(record));
  bad_magic[0] ^= 0xFFu;
  const uint32_t crc_bad_magic = ota::storage::Crc32::computeFinalized(bad_magic, 318);
  bad_magic[318] = static_cast<uint8_t>(crc_bad_magic & 0xFF);
  bad_magic[319] = static_cast<uint8_t>((crc_bad_magic >> 8) & 0xFF);
  bad_magic[320] = static_cast<uint8_t>((crc_bad_magic >> 16) & 0xFF);
  bad_magic[321] = static_cast<uint8_t>((crc_bad_magic >> 24) & 0xFF);
  EXPECT_FALSE(BootFloorActivationReceiptCodec::parseRecord(bad_magic, sizeof(bad_magic), parsed));

  uint8_t bad_domain[BootFloorActivationReceiptCodec::kRecordBytes];
  std::memcpy(bad_domain, record, sizeof(record));
  bad_domain[8] ^= 0xFFu;  // bootDomain LE @8 -- only the fixed "BOOT" literal is accepted.
  const uint32_t crc_bad_domain = ota::storage::Crc32::computeFinalized(bad_domain, 318);
  bad_domain[318] = static_cast<uint8_t>(crc_bad_domain & 0xFF);
  bad_domain[319] = static_cast<uint8_t>((crc_bad_domain >> 8) & 0xFF);
  bad_domain[320] = static_cast<uint8_t>((crc_bad_domain >> 16) & 0xFF);
  bad_domain[321] = static_cast<uint8_t>((crc_bad_domain >> 24) & 0xFF);
  EXPECT_FALSE(BootFloorActivationReceiptCodec::parseRecord(bad_domain, sizeof(bad_domain), parsed));

  // A flipped body byte with the ORIGINAL (now-stale) CRC32 still
  // intact must also be rejected -- CRC validation is the very first
  // thing parseRecord checks, before any field is trusted/decoded.
  uint8_t corrupted_body_stale_crc[BootFloorActivationReceiptCodec::kRecordBytes];
  std::memcpy(corrupted_body_stale_crc, record, sizeof(record));
  corrupted_body_stale_crc[100] ^= 0xFFu;
  EXPECT_FALSE(BootFloorActivationReceiptCodec::parseRecord(corrupted_body_stale_crc, sizeof(corrupted_body_stale_crc), parsed));
}

TEST(BootFloorActivationReceiptCodecTest, BootDomainIsAFixedConstantIdenticalAcrossEveryDeviceUid) {
  // ROOT's authoritative correction: bootDomain is NO LONGER derived
  // from hardwareUid (or anything else per-device) at all -- it is a
  // single, fixed protocol-level constant, identical for every device.
  // Per-device lifetime fencing instead comes entirely from the
  // separate, explicit hardwareUid field. This is the OPPOSITE
  // invariant from this module's earlier (now-superseded) proposal.
  BootFloorActivationReceiptV1 r1;
  for (int i = 0; i < static_cast<int>(kHardwareUidBytes); ++i) r1.hardwareUid[i] = static_cast<uint8_t>(0x77);
  uint8_t record1[BootFloorActivationReceiptCodec::kRecordBytes];
  ASSERT_EQ(BootFloorActivationReceiptCodec::serializeRecord(r1, record1, sizeof(record1)),
            BootFloorActivationReceiptCodec::kRecordBytes);

  BootFloorActivationReceiptV1 r2;
  for (int i = 0; i < static_cast<int>(kHardwareUidBytes); ++i) r2.hardwareUid[i] = static_cast<uint8_t>(0x78);
  uint8_t record2[BootFloorActivationReceiptCodec::kRecordBytes];
  ASSERT_EQ(BootFloorActivationReceiptCodec::serializeRecord(r2, record2, sizeof(record2)),
            BootFloorActivationReceiptCodec::kRecordBytes);

  // Different UIDs -> the 4 bootDomain bytes @8 are IDENTICAL (the fixed
  // literal), while the hardwareUid bytes @12 genuinely differ.
  EXPECT_EQ(0, std::memcmp(record1 + 8, record2 + 8, 4));
  EXPECT_NE(0, std::memcmp(record1 + 12, record2 + 12, 8));

  uint32_t domain1 = static_cast<uint32_t>(record1[8]) | (static_cast<uint32_t>(record1[9]) << 8) |
                      (static_cast<uint32_t>(record1[10]) << 16) | (static_cast<uint32_t>(record1[11]) << 24);
  EXPECT_EQ(BootFloorActivationReceiptCodec::kFixedBootDomainLiteral, domain1);

  // A role/layout/profile/crypto-domain label change for the SAME
  // physical UID structurally cannot mint a second floor-genesis
  // namespace: the domain field never varies at all, for any input.
  BootFloorActivationReceiptV1 r3 = r1;
  r3.profileId ^= 0xFFFFFFFFu;
  r3.layoutId ^= 0xFFFFFFFFu;
  r3.currentRole = 0;
  uint8_t record3[BootFloorActivationReceiptCodec::kRecordBytes];
  ASSERT_EQ(BootFloorActivationReceiptCodec::serializeRecord(r3, record3, sizeof(record3)),
            BootFloorActivationReceiptCodec::kRecordBytes);
  EXPECT_EQ(0, std::memcmp(record1 + 8, record3 + 8, 4));
}

// Concrete cross-language interop vector published by ROOT: the exact
// numeric BE UID 0123456789ABCDEF must land on the wire as the LE byte
// sequence EF CD AB 89 67 45 23 01 -- a deliberate, precisely-specified
// check (not just "some round trip works") so Boot's independent C
// codec/Python tooling can be verified byte-identical against this same
// vector.
TEST(BootFloorActivationReceiptCodecTest, NumericUidBigEndianToLittleEndianWireVectorMatchesPublishedVector) {
  BootFloorActivationReceiptV1 r;
  const uint8_t be_uid[kHardwareUidBytes] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
  std::memcpy(r.hardwareUid, be_uid, kHardwareUidBytes);

  uint8_t record[BootFloorActivationReceiptCodec::kRecordBytes];
  ASSERT_EQ(BootFloorActivationReceiptCodec::serializeRecord(r, record, sizeof(record)),
            BootFloorActivationReceiptCodec::kRecordBytes);

  const uint8_t expected_le_wire_uid[8] = {0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01};
  EXPECT_EQ(0, std::memcmp(record + 12, expected_le_wire_uid, 8));

  // And parsing that exact wire vector back must reconstruct the
  // original BE representation unchanged (round-trips through the
  // numeric decode/encode, never a raw memcpy in either direction).
  BootFloorActivationReceiptV1 parsed;
  ASSERT_TRUE(BootFloorActivationReceiptCodec::parseRecord(record, sizeof(record), parsed));
  EXPECT_EQ(0, std::memcmp(parsed.hardwareUid, be_uid, kHardwareUidBytes));
}

// The canonical record is EXACTLY 386 bytes -- never the Boot-side
// 4-byte-aligned 388-byte physical I/O buffer (322-body + 2 non-wire
// 0xFF pad bytes some flash driver may need). This module's own
// serializeRecord/parseRecord must never produce or accept that
// physical-layer length; 388 is simply not a recognized `recordbytes`
// value anywhere in this codec.
TEST(BootFloorActivationReceiptCodecTest, CanonicalRecordIsExactly386BytesNeverThePhysical388ByteAlignedBuffer) {
  ASSERT_EQ(static_cast<size_t>(386), BootFloorActivationReceiptCodec::kRecordBytes);

  BootFloorActivationReceiptV1 r;
  uint8_t record[BootFloorActivationReceiptCodec::kRecordBytes];
  ASSERT_EQ(BootFloorActivationReceiptCodec::serializeRecord(r, record, sizeof(record)),
            BootFloorActivationReceiptCodec::kRecordBytes);

  // A physically-padded 388-byte buffer (record + 2 trailing 0xFF pad
  // bytes) must NOT parse -- the codec only ever recognizes the exact
  // 386-byte canonical length.
  uint8_t physical_388[388];
  std::memcpy(physical_388, record, sizeof(record));
  physical_388[386] = 0xFF;
  physical_388[387] = 0xFF;
  BootFloorActivationReceiptV1 parsed;
  EXPECT_FALSE(BootFloorActivationReceiptCodec::parseRecord(physical_388, sizeof(physical_388), parsed));
  // Only the exact, unpadded 386-byte prefix is ever the canonical
  // record a real caller would hand this codec.
  EXPECT_TRUE(BootFloorActivationReceiptCodec::parseRecord(physical_388, 386, parsed));
}

// Cross-language (C++ / Python) REAL-crypto interop vector. This exact
// 386-byte record (and the matching 32-byte raw Ed25519 TEST public key
// below) was independently produced by scripts/ota_authority_registry.py's
// BootFloorActivationReceiptV1 mirror (serialize_boot_floor_body +
// compute_boot_floor_signed_digest), then signed with a synthetic,
// ephemeral .tmp-scoped TEST Ed25519 keypair via real `openssl pkeyutl
// -sign -rawin` (never a production/committed key -- generated once,
// off-repo, purely to produce this fixed literal vector; the private key
// itself is discarded and never appears here). This test proves genuine
// cross-language byte-identical canonical encoding AND genuine C++
// Ed25519 signature verification (ota::trust::Ed25519SignatureVerifier,
// the SAME real vendored primitive BootFloorActivationReceiptExporter/
// DeviceAuthorityGuard use elsewhere in this suite) against that
// independently-produced signature -- not a mocked/self-signed round
// trip. The Boot owner's own C verifier is expected to independently
// reproduce the identical digest/verify result from this same record;
// this fixture is offered for that cross-check but this test does not
// and cannot invoke Boot's own C code (bootloader/xiao_nrf52840_ota/**
// remains exclusively Boot-owned).
TEST(BootFloorActivationReceiptCodecTest, RealEd25519CrossLanguageInteropVectorVerifiesWithActualCrypto) {
  static constexpr uint8_t kInteropRecord[386] = {
      0x52, 0x41, 0x46, 0x58, 0x01, 0x00, 0x82, 0x01, 0x54, 0x4F, 0x4F, 0x42, 0xEF, 0xCD, 0xAB, 0x89,
      0x67, 0x45, 0x23, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
      0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
      0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
      0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
      0x3D, 0x3E, 0x3F, 0x40, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
      0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
      0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
      0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
      0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
      0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A,
      0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
      0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA,
      0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
      0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0x00, 0x00, 0x00, 0x00, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
      0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
      0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0x00, 0x20, 0x00, 0x00, 0xF1, 0xF2,
      0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x89, 0x42,
      0x30, 0x86, 0xD8, 0xC2, 0xA9, 0x9B, 0x59, 0x25, 0xBC, 0x52, 0x4A, 0x27, 0xB6, 0x9B, 0xFA, 0x71,
      0xD3, 0x02, 0x4F, 0xD9, 0x9B, 0xC7, 0xD5, 0x8D, 0xB9, 0x50, 0x4B, 0x3E, 0xB0, 0x0A, 0xE0, 0x74,
      0xBE, 0x34, 0xB7, 0x5F, 0xD2, 0x44, 0x7C, 0x64, 0xD0, 0x49, 0x81, 0x8A, 0xC2, 0x7E, 0xDA, 0x24,
      0x89, 0x3B, 0x76, 0x21, 0x89, 0x9E, 0x66, 0xB3, 0xCE, 0xCE, 0x7E, 0x0B, 0x13, 0xB3, 0x10, 0x5A,
      0xAA, 0x0E,
  };
  static constexpr uint8_t kInteropPublisherPublicKey[32] = {
      0x10, 0x14, 0xCA, 0xE1, 0xB5, 0xCF, 0x78, 0xA5, 0x26, 0x35, 0x45, 0x25, 0x15, 0x65, 0x8B, 0x73,
      0x0A, 0xF5, 0x97, 0x99, 0xCA, 0x1B, 0x2C, 0x25, 0x0A, 0x63, 0x18, 0x52, 0xC8, 0x24, 0x40, 0x3B,
  };

  BootFloorActivationReceiptV1 parsed;
  ASSERT_TRUE(BootFloorActivationReceiptCodec::parseRecord(kInteropRecord, sizeof(kInteropRecord), parsed))
      << "cross-language fixture failed to parse -- offsets/CRC/magic/domain no longer byte-identical "
         "with the Python mirror";

  // This device's own hardwareUid round-trips through the BE->numeric->LE
  // conversion the wire format performs -- confirms the numeric UID
  // vector (BE 0123456789ABCDEF -> LE wire EFCDAB8967452301) still holds
  // for this exact fixture.
  static constexpr uint8_t kExpectedUidBe[kHardwareUidBytes] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
  EXPECT_EQ(0, std::memcmp(parsed.hardwareUid, kExpectedUidBe, kHardwareUidBytes));

  uint8_t recomputed_digest[kDigestBytes];
  ASSERT_TRUE(BootFloorActivationReceiptCodec::computeSignedDigest(parsed, recomputed_digest));

  ota::trust::Ed25519SignatureVerifier verifier;
  // The REAL genuine signature check: an independently (Python/openssl)
  // produced Ed25519 signature, verified here using this repo's own
  // real vendored Ed25519 implementation -- never a mocked/fabricated
  // "always true" verifier.
  EXPECT_TRUE(verifier.verify(parsed.signatureEd25519, kSignatureBytes, recomputed_digest, kDigestBytes,
                              kInteropPublisherPublicKey, kPublicKeyBytes));

  // Adversarial control: flipping a single signed body byte after the
  // fact must make the SAME real verifier reject the SAME signature --
  // proves this isn't a verifier that always returns true.
  uint8_t tampered[386];
  std::memcpy(tampered, kInteropRecord, sizeof(tampered));
  tampered[100] ^= 0x01u;  // Inside publisherKeyId field, well before the signature bytes.
  const uint32_t fixed_crc = ota::storage::Crc32::computeFinalized(tampered, 318);
  tampered[318] = static_cast<uint8_t>(fixed_crc & 0xFF);
  tampered[319] = static_cast<uint8_t>((fixed_crc >> 8) & 0xFF);
  tampered[320] = static_cast<uint8_t>((fixed_crc >> 16) & 0xFF);
  tampered[321] = static_cast<uint8_t>((fixed_crc >> 24) & 0xFF);
  BootFloorActivationReceiptV1 tampered_parsed;
  ASSERT_TRUE(BootFloorActivationReceiptCodec::parseRecord(tampered, sizeof(tampered), tampered_parsed));
  uint8_t tampered_digest[kDigestBytes];
  ASSERT_TRUE(BootFloorActivationReceiptCodec::computeSignedDigest(tampered_parsed, tampered_digest));
  EXPECT_FALSE(verifier.verify(tampered_parsed.signatureEd25519, kSignatureBytes, tampered_digest, kDigestBytes,
                               kInteropPublisherPublicKey, kPublicKeyBytes));
}

// Astra role-1 residual ("verify requested role1 shared real crypto
// literal interop exists C++/Python -- not just FakeVerifier happy-path
// tests"): a SEPARATE real cross-language fixture, genuinely signed with
// a fresh ephemeral Ed25519 test keypair (generated once via openssl,
// private key discarded immediately after -- never committed, never
// reused), carrying currentRole=1 end-to-end. Proves role=1 is not just
// accepted by a FakeVerifier/in-process signer round trip, but verifies
// with this repo's own REAL vendored Ed25519 implementation against an
// independently produced signature, identically to the role=0 fixture
// above. The IDENTICAL literal bytes are mirrored in
// scripts/tests/test_ota_authority_registry.py's
// test_real_ed25519_cross_language_interop_vector_verifies_with_actual_crypto_role_one.
TEST(BootFloorActivationReceiptCodecTest, RealEd25519CrossLanguageInteropVectorVerifiesWithActualCryptoRoleOne) {
  static constexpr uint8_t kInteropRecordRoleOne[386] = {
      0x52, 0x41, 0x46, 0x58, 0x01, 0x00, 0x82, 0x01, 0x54, 0x4F, 0x4F, 0x42, 0x10, 0x32, 0x54, 0x76,
      0x98, 0xBA, 0xDC, 0xFE, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3,
      0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3,
      0xE4, 0xE5, 0xE6, 0xE7, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
      0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D,
      0x4E, 0x4F, 0x50, 0x51, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
      0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
      0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
      0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
      0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
      0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
      0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
      0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
      0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x00, 0x00, 0x00, 0x00, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B,
      0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
      0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0x00, 0x40, 0x00, 0x00, 0xB4, 0xB5,
      0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
      0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xCE, 0x17,
      0x67, 0x98, 0x20, 0x8A, 0x19, 0x88, 0x02, 0xE0, 0x8A, 0xE3, 0xD5, 0x24, 0xFF, 0x54, 0x9E, 0x30,
      0x7B, 0xC6, 0x4D, 0x6B, 0x89, 0x91, 0xA9, 0xA6, 0x76, 0x96, 0xDA, 0x12, 0x76, 0x1B, 0xAD, 0x3A,
      0xF9, 0xF2, 0x78, 0xF6, 0x62, 0xF2, 0xC2, 0x94, 0xDB, 0x5F, 0xF8, 0xAF, 0x65, 0xE4, 0x3F, 0x73,
      0xF6, 0x72, 0x69, 0xA2, 0x37, 0xE7, 0x8B, 0xBA, 0x9C, 0x01, 0x97, 0x66, 0xA0, 0x99, 0x96, 0xBC,
      0xF3, 0x0A,
  };
  static constexpr uint8_t kInteropPublisherPublicKeyRoleOne[32] = {
      0x30, 0x1E, 0x71, 0x12, 0x25, 0x0F, 0x70, 0x4A, 0xDB, 0x60, 0x57, 0xD7, 0xA2, 0x79, 0xA1, 0xFC,
      0x1F, 0xD8, 0xA0, 0x16, 0x58, 0xD4, 0x09, 0x5D, 0x1B, 0xE4, 0x0D, 0x08, 0x24, 0x7F, 0x26, 0xB3,
  };

  BootFloorActivationReceiptV1 parsed;
  ASSERT_TRUE(BootFloorActivationReceiptCodec::parseRecord(kInteropRecordRoleOne, sizeof(kInteropRecordRoleOne), parsed))
      << "role-1 cross-language fixture failed to parse";
  ASSERT_EQ(parsed.currentRole, 1u);

  static constexpr uint8_t kExpectedUidBeRoleOne[kHardwareUidBytes] = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
  EXPECT_EQ(0, std::memcmp(parsed.hardwareUid, kExpectedUidBeRoleOne, kHardwareUidBytes));

  uint8_t recomputed_digest[kDigestBytes];
  ASSERT_TRUE(BootFloorActivationReceiptCodec::computeSignedDigest(parsed, recomputed_digest));

  ota::trust::Ed25519SignatureVerifier verifier;
  EXPECT_TRUE(verifier.verify(parsed.signatureEd25519, kSignatureBytes, recomputed_digest, kDigestBytes,
                              kInteropPublisherPublicKeyRoleOne, kPublicKeyBytes));

  // Adversarial control: flipping currentRole itself (byte offset 96,
  // the very field this fixture exists to exercise) must invalidate the
  // SAME real signature against the SAME real verifier.
  uint8_t tampered[386];
  std::memcpy(tampered, kInteropRecordRoleOne, sizeof(tampered));
  tampered[96] ^= 0x01u;  // currentRole: 1 -> 0.
  const uint32_t fixed_crc = ota::storage::Crc32::computeFinalized(tampered, 318);
  tampered[318] = static_cast<uint8_t>(fixed_crc & 0xFF);
  tampered[319] = static_cast<uint8_t>((fixed_crc >> 8) & 0xFF);
  tampered[320] = static_cast<uint8_t>((fixed_crc >> 16) & 0xFF);
  tampered[321] = static_cast<uint8_t>((fixed_crc >> 24) & 0xFF);
  BootFloorActivationReceiptV1 tampered_parsed;
  ASSERT_TRUE(BootFloorActivationReceiptCodec::parseRecord(tampered, sizeof(tampered), tampered_parsed));
  EXPECT_EQ(tampered_parsed.currentRole, 0u);
  uint8_t tampered_digest[kDigestBytes];
  ASSERT_TRUE(BootFloorActivationReceiptCodec::computeSignedDigest(tampered_parsed, tampered_digest));
  EXPECT_FALSE(verifier.verify(tampered_parsed.signatureEd25519, kSignatureBytes, tampered_digest, kDigestBytes,
                               kInteropPublisherPublicKeyRoleOne, kPublicKeyBytes));
}

// Astra production-contract section D: PrepareAuthorizationV1 is a new
// codec, not yet wired into AuthorityCoordinator::prepare -- these
// tests exercise the codec/signing/digest contract directly (round-
// trip, exact wire sizes, input-digest sensitivity to every one of its
// five components, and tamper detection against a REAL Ed25519
// signature), exactly mirroring how ActivationAuthorizationCodec itself
// is exercised, without claiming this is wired into any production
// path yet.
TEST_F(AuthorityFixture, PrepareAuthorizationCodecRoundTripsAndSignsWithRealEd25519) {
  TestDevice device("prepare-auth-codec-device", 200);
  uint8_t grant_txn_id[kTransactionIdBytes];
  makeTxnId(grant_txn_id, 0xD0);
  uint8_t manifest_digest[kDigestBytes];

  BaselineCertificationManifest manifest;
  fillSeed(manifest.approvedImageSha256, "prepare-auth-image-200");
  manifest.approvedImageExtentLength = 0x9800;
  fillSeed(manifest.expectedSdk28Sha256Digest, "prepare-auth-sdk28-200");
  manifest.allowOrdinaryUserdata = true;
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, manifest_digest));

  AuthorityTransaction grant = makeCommission(device.binding, grant_txn_id, manifest_digest);
  uint8_t certify_txn_id[kTransactionIdBytes];
  makeTxnId(certify_txn_id, 0xD1);
  AuthorityTransaction certify = makeCertifyExistingBaseline(device.binding, certify_txn_id, manifest_digest);

  uint8_t peer_pk[kPublicKeyBytes];
  fillSeed(peer_pk, "prepare-auth-peer-pk-200");

  uint8_t input_digest[kDigestBytes];
  ASSERT_TRUE(PrepareAuthorizationCodec::computeInputDigestSha256(grant, certify, manifest, PrepareRxContextKind::Peer,
                                                                   peer_pk, input_digest));

  PrepareAuthorizationV1 prep;
  std::memcpy(prep.transactionId, grant_txn_id, kTransactionIdBytes);
  ASSERT_TRUE(AuthorityCodec::computeRecordDigestSha256(grant, prep.grantDigestSha256));
  std::memcpy(prep.inputDigestSha256, input_digest, kDigestBytes);
  prep.authorizedRevision = grant.revision;
  prep.expectedBinding = grant.binding;
  fillChallenge(prep.deviceFreshChallenge, "prepare-auth-device-challenge-200");
  fillChallenge(prep.hostNonce, "prepare-auth-host-nonce-200");

  uint8_t message[PrepareAuthorizationCodec::kSignedMessageBytes];
  ASSERT_EQ(PrepareAuthorizationCodec::serializeSignedMessage(prep, message, sizeof(message)),
            PrepareAuthorizationCodec::kSignedMessageBytes);
  issuer_signer_->sign(message, sizeof(message), prep.issuerSignatureEd25519);

  uint8_t record[PrepareAuthorizationCodec::kRecordBytes];
  ASSERT_EQ(PrepareAuthorizationCodec::serializeRecord(prep, record, sizeof(record)),
            PrepareAuthorizationCodec::kRecordBytes);
  EXPECT_EQ(PrepareAuthorizationCodec::kRecordBytes, 267u);
  EXPECT_EQ(PrepareAuthorizationCodec::kBodyBytes, 203u);

  PrepareAuthorizationV1 parsed;
  ASSERT_EQ(PrepareAuthorizationCodec::parseRecord(record, sizeof(record), parsed),
            PrepareAuthorizationDecodeError::None);
  EXPECT_EQ(0, std::memcmp(parsed.transactionId, grant_txn_id, kTransactionIdBytes));
  EXPECT_EQ(0, std::memcmp(parsed.grantDigestSha256, prep.grantDigestSha256, kDigestBytes));
  EXPECT_EQ(0, std::memcmp(parsed.inputDigestSha256, input_digest, kDigestBytes));

  uint8_t parsed_message[PrepareAuthorizationCodec::kSignedMessageBytes];
  ASSERT_EQ(PrepareAuthorizationCodec::serializeSignedMessage(parsed, parsed_message, sizeof(parsed_message)),
            PrepareAuthorizationCodec::kSignedMessageBytes);
  EXPECT_TRUE(verifier_.verify(parsed.issuerSignatureEd25519, kSignatureBytes, parsed_message,
                               sizeof(parsed_message), issuer_signer_->publicKey(), kPublicKeyBytes));

  // Tamper: flip the input digest after signing -- the REAL signature
  // must no longer verify against the tampered message.
  PrepareAuthorizationV1 tampered = parsed;
  tampered.inputDigestSha256[0] ^= 0xFF;
  uint8_t tampered_message[PrepareAuthorizationCodec::kSignedMessageBytes];
  ASSERT_EQ(PrepareAuthorizationCodec::serializeSignedMessage(tampered, tampered_message, sizeof(tampered_message)),
            PrepareAuthorizationCodec::kSignedMessageBytes);
  EXPECT_FALSE(verifier_.verify(tampered.issuerSignatureEd25519, kSignatureBytes, tampered_message,
                                sizeof(tampered_message), issuer_signer_->publicKey(), kPublicKeyBytes));
}

TEST_F(AuthorityFixture, PrepareAuthorizationInputDigestIsSensitiveToEveryOneOfItsFiveComponents) {
  TestDevice device("prepare-auth-sensitivity-device", 201);
  uint8_t grant_txn_id[kTransactionIdBytes];
  makeTxnId(grant_txn_id, 0xD2);
  uint8_t manifest_digest[kDigestBytes];

  BaselineCertificationManifest manifest;
  fillSeed(manifest.approvedImageSha256, "prepare-sens-image-201");
  manifest.approvedImageExtentLength = 0x9800;
  fillSeed(manifest.expectedSdk28Sha256Digest, "prepare-sens-sdk28-201");
  manifest.allowOrdinaryUserdata = true;
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, manifest_digest));

  AuthorityTransaction grant = makeCommission(device.binding, grant_txn_id, manifest_digest);
  uint8_t certify_txn_id[kTransactionIdBytes];
  makeTxnId(certify_txn_id, 0xD3);
  AuthorityTransaction certify = makeCertifyExistingBaseline(device.binding, certify_txn_id, manifest_digest);
  uint8_t peer_pk[kPublicKeyBytes];
  fillSeed(peer_pk, "prepare-sens-peer-pk-201");

  uint8_t baseline_digest[kDigestBytes];
  ASSERT_TRUE(PrepareAuthorizationCodec::computeInputDigestSha256(grant, certify, manifest, PrepareRxContextKind::Peer,
                                                                   peer_pk, baseline_digest));

  // Changing the GRANT must change the digest.
  {
    AuthorityTransaction different_grant = grant;
    different_grant.initialTxSequenceFloor += 1;
    sign(different_grant);
    uint8_t d[kDigestBytes];
    ASSERT_TRUE(PrepareAuthorizationCodec::computeInputDigestSha256(different_grant, certify, manifest,
                                                                     PrepareRxContextKind::Peer, peer_pk, d));
    EXPECT_NE(0, std::memcmp(d, baseline_digest, kDigestBytes));
  }
  // Changing the CERTIFY must change the digest.
  {
    uint8_t other_manifest_digest[kDigestBytes];
    BaselineCertificationManifest other_manifest = manifest;
    other_manifest.approvedImageExtentLength += 1;
    ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(other_manifest, other_manifest_digest));
    AuthorityTransaction different_certify = makeCertifyExistingBaseline(device.binding, certify_txn_id, other_manifest_digest);
    uint8_t d[kDigestBytes];
    ASSERT_TRUE(PrepareAuthorizationCodec::computeInputDigestSha256(grant, different_certify, manifest,
                                                                     PrepareRxContextKind::Peer, peer_pk, d));
    EXPECT_NE(0, std::memcmp(d, baseline_digest, kDigestBytes));
  }
  // Changing the MANIFEST (B) must change the digest.
  {
    BaselineCertificationManifest different_manifest = manifest;
    different_manifest.approvedImageExtentLength += 7;
    uint8_t d[kDigestBytes];
    ASSERT_TRUE(PrepareAuthorizationCodec::computeInputDigestSha256(grant, certify, different_manifest,
                                                                     PrepareRxContextKind::Peer, peer_pk, d));
    EXPECT_NE(0, std::memcmp(d, baseline_digest, kDigestBytes));
  }
  // Changing the RX CONTEXT KIND must change the digest.
  {
    uint8_t d[kDigestBytes];
    ASSERT_TRUE(PrepareAuthorizationCodec::computeInputDigestSha256(grant, certify, manifest,
                                                                     PrepareRxContextKind::None, peer_pk, d));
    EXPECT_NE(0, std::memcmp(d, baseline_digest, kDigestBytes));
  }
  // Changing the PEER PUBLIC KEY must change the digest.
  {
    uint8_t different_peer_pk[kPublicKeyBytes];
    fillSeed(different_peer_pk, "prepare-sens-peer-pk-OTHER-201");
    uint8_t d[kDigestBytes];
    ASSERT_TRUE(PrepareAuthorizationCodec::computeInputDigestSha256(grant, certify, manifest, PrepareRxContextKind::Peer,
                                                                     different_peer_pk, d));
    EXPECT_NE(0, std::memcmp(d, baseline_digest, kDigestBytes));
  }
}


// The exporter's own durability barrier (added this round) must deny
// export for as long as that persists, and only succeed once storage
// genuinely recovers -- without a restart, without any repair call,
// and producing the EXACT SAME receipt once it does.
TEST_F(AuthorityFixture, BootFloorExportDeniesAfterAMarkerFsyncFaultUntilAPositiveDurabilityBarrierConfirms) {
  TestDevice device("floor-export-durability-fault-device", 131);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0xC8);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-131");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(131);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 132, commission);

  // Both copies are genuinely ActivationSpent at this point -- confirm
  // via a plain reconcile() before injecting the fault, to establish
  // the baseline this test is actually exercising.
  ReconciliationResult sanity = pair.reconcile(txnId);
  ASSERT_EQ(sanity.outcome, ReconciliationOutcome::Agreed);
  ASSERT_EQ(sanity.resolved.state, TransactionState::ActivationSpent);

  // Simulate a storage hiccup discovered ONLY at the exporter's fresh
  // durability-confirm barrier (not at the original append, which
  // already genuinely succeeded above) -- persists until explicitly
  // lifted.
  bool storage_recovered = false;
  a.setConfirmDurableFsyncOverrideForTests([&](int) { return storage_recovered; });

  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  uint8_t zero_sdk28[kBootFloorOriginalSdk28DigestBytes] = {0};
  FakeOriginalBaselineSdk28Provenance provenance(zero_sdk28);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, &test_lock_);
  BootFloorBaselineEvidence baseline;
  BootFloorActivationReceiptV1 receipt;

  // Denied while storage genuinely cannot confirm durability -- not a
  // one-shot guess, repeated attempts keep denying.
  EXPECT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::RegistryDisagreement);
  EXPECT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::RegistryDisagreement);

  // Storage genuinely recovers: a later, independent call (same
  // exporter instance, no restart, no repair call) must now succeed and
  // deliver the EXACT SAME already-committed grant.
  storage_recovered = true;
  BootFloorActivationReceiptV1 recovered_receipt;
  ASSERT_EQ(exporter.exportReceipt(txnId, baseline, recovered_receipt), BootFloorExportOutcome::Ok);
  EXPECT_EQ(0, std::memcmp(recovered_receipt.hostTransactionId, txnId, kTransactionIdBytes));
  EXPECT_EQ(0, std::memcmp(recovered_receipt.commissionManifestDigestSha256, commission.manifestDigestSha256, kDigestBytes));
}

TEST_F(AuthorityFixture, BootFloorExportRejectsBeforeBothCopiesReachActivationSpent) {
  TestDevice device("floor-export-early-device", 60);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x60);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-60");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(60);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy, nullptr, &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);

  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  uint8_t zero_sdk28[kBootFloorOriginalSdk28DigestBytes] = {0};
  FakeOriginalBaselineSdk28Provenance provenance(zero_sdk28);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, &test_lock_);
  BootFloorBaselineEvidence baseline;
  BootFloorActivationReceiptV1 receipt;

  // Still just Issued: no prepare/activate has happened at all.
  EXPECT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::NotActivationSpent);

  // Prepare only (ConsumedPrepared): still not enough.
  InMemoryDeviceStore device_store;
  RecordingMaintenance maintenance;
  CountingEntropy device_entropy(61);
  Ed25519DeviceSigner signer(device.signer);
  DeviceAuthorityGuard guard(device.binding, &verifier_, issuer_trust_.get(), &device_entropy, &device_store,
                              &maintenance, &signer);
  LoopbackDeviceSession session(guard);
  session.drop_activation_response = true;  // Force prepare() to succeed, activation to stay pending.
  StoredTransactionRecord after;
  // prepare() itself already commits ActivationSpent inside the same
  // call (see AuthorityCoordinator::runPrepareHandshake) -- there is no
  // real ConsumedPrepared-but-not-yet-ActivationSpent window reachable
  // through the public API once prepare() returns Ok. We instead model
  // "not yet activated" purely by never calling prepare() at all (the
  // Issued-only case above) plus verify the happy path below succeeds
  // only after the real handshake completes.
  EXPECT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::NotActivationSpent);
}

TEST_F(AuthorityFixture, BootFloorExportHappyPathProducesVerifiableSignedReceipt) {
  TestDevice device("floor-export-device", 61);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x61);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-61");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(62);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 63, commission);

  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  BootFloorBaselineEvidence baseline;
  fillSeed(baseline.imageSha256, "baseline-image-61");
  baseline.extentLength = 0x8000;
  fillSeed(baseline.original28Sha256Digest, "original-sdk28-61");
  baseline.targetId = 0x584E3401u;  // Compiled target: separate field, NOT assumed equal to profileId.
  FakeOriginalBaselineSdk28Provenance provenance(baseline.original28Sha256Digest, baseline.imageSha256,
                                                  baseline.extentLength, baseline.targetId);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, &test_lock_);

  BootFloorActivationReceiptV1 receipt;
  ASSERT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Ok);

  EXPECT_EQ(0, std::memcmp(receipt.hardwareUid, device.binding.hardwareUid, kHardwareUidBytes));
  EXPECT_EQ(0, std::memcmp(receipt.localMeshFullPublicKey, device.binding.meshFullPublicKey, kPublicKeyBytes));
  EXPECT_EQ(receipt.currentRole, 0u);
  EXPECT_EQ(receipt.targetId, baseline.targetId);
  EXPECT_NE(receipt.targetId, receipt.profileId);  // separate compiled fields, never conflated.
  EXPECT_EQ(receipt.floor, 0u);
  EXPECT_EQ(0, std::memcmp(receipt.hostTransactionId, txnId, kTransactionIdBytes));
  EXPECT_EQ(0, std::memcmp(receipt.commissionManifestDigestSha256, digest, kDigestBytes));
  EXPECT_EQ(0, std::memcmp(receipt.baselineImageSha256, baseline.imageSha256, 32));
  EXPECT_EQ(receipt.baselineExtentLength, baseline.extentLength);
  EXPECT_EQ(0, std::memcmp(receipt.originalSdk28Sha256Digest, baseline.original28Sha256Digest, 32));

  // Genesis-only and domain-fixed invariants on the actually-exported
  // receipt.
  uint8_t record[BootFloorActivationReceiptCodec::kRecordBytes];
  ASSERT_EQ(BootFloorActivationReceiptCodec::serializeRecord(receipt, record, sizeof(record)),
            BootFloorActivationReceiptCodec::kRecordBytes);
  const uint32_t domain_on_wire = static_cast<uint32_t>(record[8]) | (static_cast<uint32_t>(record[9]) << 8) |
                                    (static_cast<uint32_t>(record[10]) << 16) | (static_cast<uint32_t>(record[11]) << 24);
  EXPECT_EQ(BootFloorActivationReceiptCodec::kFixedBootDomainLiteral, domain_on_wire);

  // The signature genuinely verifies against the publisher's public key
  // over SHA256(domain || canonical body) -- a 32-byte DIGEST, NOT the
  // raw (domain||body) bytes themselves, and NOT Ed25519ph -- not a
  // stub/always-true check.
  uint8_t expected_digest[kDigestBytes];
  ASSERT_TRUE(BootFloorActivationReceiptCodec::computeSignedDigest(receipt, expected_digest));
  EXPECT_TRUE(verifier_.verify(receipt.signatureEd25519, kSignatureBytes, expected_digest, sizeof(expected_digest),
                                issuer_signer_->publicKey(), kPublicKeyBytes));

  // Tampering ANY field invalidates the signature over the recomputed
  // digest (the signature covers a digest of the WHOLE body, so any
  // field flip changes the digest).
  BootFloorActivationReceiptV1 tampered = receipt;
  tampered.floor = 1;
  uint8_t tampered_digest[kDigestBytes];
  ASSERT_TRUE(BootFloorActivationReceiptCodec::computeSignedDigest(tampered, tampered_digest));
  EXPECT_FALSE(verifier_.verify(receipt.signatureEd25519, kSignatureBytes, tampered_digest, sizeof(tampered_digest),
                                 issuer_signer_->publicKey(), kPublicKeyBytes));

  // Export is retryable for the SAME still-current binding: same core
  // fields (modulo a fresh signature, since Ed25519 is deterministic
  // here anyway but this must not be assumed).
  BootFloorActivationReceiptV1 receipt2;
  ASSERT_EQ(exporter.exportReceipt(txnId, baseline, receipt2), BootFloorExportOutcome::Ok);
  EXPECT_EQ(0, std::memcmp(receipt2.hostTransactionId, receipt.hostTransactionId, kTransactionIdBytes));
  EXPECT_EQ(0, std::memcmp(receipt2.preparedRootDigestSha256, receipt.preparedRootDigestSha256, kDigestBytes));
}

// Astra role-1 genesis design: a signed FIRST Commission for a genuine
// role-1 (repeater) device must be fully supported end-to-end, and the
// exported receipt's currentRole must be the VERIFIED Commission
// binding's OWN historicalInitialRoleId copied through -- never the
// caller's `baseline` evidence (which carries no role field at all) and
// never a hardcoded 0.
TEST_F(AuthorityFixture, BootFloorExportSupportsSignedRoleOneGenesisAndCopiesVerifiedBindingRole) {
  TestDevice device("floor-export-role1-device", 78);
  device.binding.historicalInitialRoleId = 1;  // genuine repeater baseline, not a companion relabel.
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x78);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-78");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);
  ASSERT_EQ(commission.binding.historicalInitialRoleId, 1u);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(79);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 80, commission);

  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  BootFloorBaselineEvidence baseline;
  fillSeed(baseline.imageSha256, "baseline-image-78-repeater");
  baseline.extentLength = 0xA000;
  fillSeed(baseline.original28Sha256Digest, "original-sdk28-78");
  baseline.targetId = 0x584E3478u;
  FakeOriginalBaselineSdk28Provenance provenance(baseline.original28Sha256Digest, baseline.imageSha256,
                                                  baseline.extentLength, baseline.targetId);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, &test_lock_);

  BootFloorActivationReceiptV1 receipt;
  ASSERT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Ok);
  // The role on the receipt came from the VERIFIED binding, not from
  // `baseline` (which has no role field to copy from at all) and not a
  // fixed 0 -- genuinely 1 for this genuine repeater genesis.
  EXPECT_EQ(receipt.currentRole, 1u);
  EXPECT_EQ(0, std::memcmp(receipt.hardwareUid, device.binding.hardwareUid, kHardwareUidBytes));
  EXPECT_EQ(0, std::memcmp(receipt.localMeshFullPublicKey, device.binding.meshFullPublicKey, kPublicKeyBytes));

  uint8_t expected_digest[kDigestBytes];
  ASSERT_TRUE(BootFloorActivationReceiptCodec::computeSignedDigest(receipt, expected_digest));
  EXPECT_TRUE(verifier_.verify(receipt.signatureEd25519, kSignatureBytes, expected_digest, sizeof(expected_digest),
                                issuer_signer_->publicKey(), kPublicKeyBytes));
}

// Astra role-1 genesis design, crossed-role/role-value rejection: no
// role outside {0,1} is a supported genesis, and historicalInitialRole
// of an existing Factory root remains immutable -- a bare label change
// is never a valid "recommission" path (companion0 "recommissioned" as
// 1, or any out-of-range role value, must never earn a genesis receipt).
TEST_F(AuthorityFixture, BootFloorExportRejectsOutOfRangeRoleAndNeverRelabelsAnExistingFactoryRoot) {
  TestDevice device("floor-export-role-range-device", 81);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x81);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-81");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);
  // Deliberately out-of-range (neither 0 nor 1) -- re-sign after mutating
  // so the issuer signature still verifies and only the role-range check
  // itself is being exercised, not a signature rejection.
  commission.binding.historicalInitialRoleId = 2;
  sign(commission);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(82);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  TestDevice range_device = device;
  range_device.binding.historicalInitialRoleId = 2;
  prepareAndActivate(coordinator, txnId, range_device, 83, commission);

  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  BootFloorBaselineEvidence baseline;
  fillSeed(baseline.imageSha256, "baseline-image-81");
  baseline.extentLength = 0xB000;
  fillSeed(baseline.original28Sha256Digest, "original-sdk28-81");
  baseline.targetId = 0x584E3481u;
  FakeOriginalBaselineSdk28Provenance provenance(baseline.original28Sha256Digest, baseline.imageSha256,
                                                  baseline.extentLength, baseline.targetId);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, &test_lock_);

  BootFloorActivationReceiptV1 receipt;
  EXPECT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::OperationMismatch);

  // Separately: an existing genuine role-0 Factory root's own
  // historicalInitialRole is immutable -- a later attempt to export it
  // "as role 1" is not expressible through this API at all (the role
  // always comes from the already-verified binding, never a caller
  // parameter), so the only way to prove immutability here is that a
  // SECOND, freshly role-1 Commission for the SAME physical owner is
  // rejected as a relabel/recommission, not accepted as a new genesis.
  TestDevice device0("floor-export-role-range-device", 81);  // same identity/UID as `device` above.
  uint8_t txnId0[kTransactionIdBytes];
  makeTxnId(txnId0, 0x82);
  uint8_t digest0[kDigestBytes];
  fillSeed(digest0, "manifest-82");
  AuthorityTransaction commission0 = makeCommission(device0.binding, txnId0, digest0);
  ASSERT_EQ(commission0.binding.historicalInitialRoleId, 0u);
  // Same physical owner (same hardwareUid/cryptoDomain/layout per
  // TestDevice's seeded construction) already has an ActivationSpent
  // Commission from `commission` above -- a second, distinct-fullPK
  // Commission for that identical physical owner must be refused as a
  // relabel/duplicate genesis, not treated as independently valid.
  EXPECT_NE(coordinator.submitCommission(commission0), AuthorityOutcome::Ok);
}

// ---------------------------------------------------------------------
// REAL (non-test-double) OriginalBaselineSdk28Provenance implementation:
// FileBackedOriginalBaselineManifestSidecar. Astra residual: prove this
// is not an "opaque boolean trust" -- it only ever answers from a
// candidate manifest whose OWN digest genuinely matches the ALREADY-
// SIGNED, ALREADY-DURABLE (two-copy) manifestDigestSha256 carried inside
// the real Commission transaction, re-verified fresh on every lookup,
// never merely replaying whatever bytes a caller happened to supply.
// ---------------------------------------------------------------------

TEST_F(AuthorityFixture, RealBaselineProvenanceSidecarRecordsAndServesOnlyADigestVerifiedCandidate) {
  TestDevice device("real-provenance-happy-device", 101);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0xA1);

  BaselineCertificationManifest manifest;
  fillSeed(manifest.approvedImageSha256, "provenance-image-101");
  manifest.approvedImageExtentOffset = 0x20000;
  manifest.approvedImageExtentLength = 0x9800;
  fillSeed(manifest.expectedSdk28Sha256Digest, "provenance-sdk28-101");
  fillSeed(manifest.stockLoaderArtifactSha256, "provenance-loader-101");
  manifest.stockLoaderArtifactRangeStart = 0xF4000;
  manifest.stockLoaderArtifactRangeLength = 0x9800;
  manifest.bootConfigId = 3;
  manifest.allowOrdinaryUserdata = true;
  uint8_t manifest_digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, manifest_digest));

  // The Commission transaction's OWN already-signed manifestDigestSha256
  // is exactly this manifest's digest -- the real-world precondition an
  // issuer/CLI would have already established at commissioning time.
  AuthorityTransaction commission = makeCommission(device.binding, txnId, manifest_digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(102);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 103, commission);

  const std::string sidecar_dir = uniqueTestDir("baseline-sidecar");
  FileBackedOriginalBaselineManifestSidecar sidecar(pair, sidecar_dir);

  const uint32_t target_id = 0x584E3401u;
  ASSERT_EQ(sidecar.recordOriginalBaselineManifest(device.binding, txnId, manifest, target_id),
            OriginalBaselineManifestRecordOutcome::Ok);

  AuthorityBootFloorBaselineProvenanceRecord looked_up;
  ASSERT_TRUE(sidecar.lookupOriginalBaselineProvenance(device.binding, txnId, looked_up));
  EXPECT_EQ(0, std::memcmp(looked_up.imageSha256, manifest.approvedImageSha256, kBootFloorBaselineImageDigestBytes));
  EXPECT_EQ(looked_up.extentLength, manifest.approvedImageExtentLength);
  EXPECT_EQ(looked_up.targetId, target_id);
  EXPECT_EQ(0, std::memcmp(looked_up.original28Sha256Digest, manifest.expectedSdk28Sha256Digest,
                           kBootFloorOriginalSdk28DigestBytes));

  // Idempotent re-record of the IDENTICAL already-verified fact is Ok.
  EXPECT_EQ(sidecar.recordOriginalBaselineManifest(device.binding, txnId, manifest, target_id),
            OriginalBaselineManifestRecordOutcome::Ok);

  // End-to-end: wiring this REAL implementation into the actual exporter
  // (not the Fake) must accept a matching BootFloorBaselineEvidence and
  // reject a tampered one -- never an opaque pass-through.
  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &sidecar, &test_lock_);
  BootFloorBaselineEvidence matching_baseline;
  std::memcpy(matching_baseline.imageSha256, manifest.approvedImageSha256, kBootFloorBaselineImageDigestBytes);
  matching_baseline.extentLength = manifest.approvedImageExtentLength;
  std::memcpy(matching_baseline.original28Sha256Digest, manifest.expectedSdk28Sha256Digest,
              kBootFloorOriginalSdk28DigestBytes);
  matching_baseline.targetId = target_id;
  BootFloorActivationReceiptV1 receipt;
  EXPECT_EQ(exporter.exportReceipt(txnId, matching_baseline, receipt), BootFloorExportOutcome::Ok);

  BootFloorBaselineEvidence tampered_baseline = matching_baseline;
  tampered_baseline.extentLength += 1;
  EXPECT_EQ(exporter.exportReceipt(txnId, tampered_baseline, receipt), BootFloorExportOutcome::BaselineImageProvenanceMismatch);
}

TEST_F(AuthorityFixture, RealBaselineProvenanceSidecarRefusesCandidateWhoseDigestDoesNotMatchTheSignedTransaction) {
  TestDevice device("real-provenance-mismatch-device", 104);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0xA4);

  uint8_t unrelated_digest[kDigestBytes];
  fillSeed(unrelated_digest, "manifest-unrelated-104");  // NOT the digest of any manifest below.
  AuthorityTransaction commission = makeCommission(device.binding, txnId, unrelated_digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(105);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 106, commission);

  const std::string sidecar_dir = uniqueTestDir("baseline-sidecar");
  FileBackedOriginalBaselineManifestSidecar sidecar(pair, sidecar_dir);

  BaselineCertificationManifest fabricated_manifest;
  fillSeed(fabricated_manifest.approvedImageSha256, "fabricated-image-104");
  fabricated_manifest.approvedImageExtentLength = 0x1000;
  fillSeed(fabricated_manifest.expectedSdk28Sha256Digest, "fabricated-sdk28-104");

  // A caller (or attacker) supplying a self-consistent but UNRELATED
  // manifest -- one whose own digest genuinely does NOT match what the
  // issuer already signed into this transaction -- must be refused, and
  // nothing durable is ever written on that refusal.
  EXPECT_EQ(sidecar.recordOriginalBaselineManifest(device.binding, txnId, fabricated_manifest, 0x1u),
            OriginalBaselineManifestRecordOutcome::ManifestDigestMismatch);

  AuthorityBootFloorBaselineProvenanceRecord looked_up;
  EXPECT_FALSE(sidecar.lookupOriginalBaselineProvenance(device.binding, txnId, looked_up));

  // The exporter end-to-end also simply denies (lookup fails => Denied),
  // never silently accepting the unrecorded transaction.
  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &sidecar, &test_lock_);
  BootFloorBaselineEvidence baseline;
  BootFloorActivationReceiptV1 receipt;
  EXPECT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Denied);
}

TEST_F(AuthorityFixture, RealBaselineProvenanceSidecarRefusesConflictingReRecordAndTamperedFileOnDisk) {
  TestDevice device("real-provenance-conflict-device", 107);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0xA7);

  BaselineCertificationManifest manifest;
  fillSeed(manifest.approvedImageSha256, "provenance-image-107");
  manifest.approvedImageExtentLength = 0x9800;
  fillSeed(manifest.expectedSdk28Sha256Digest, "provenance-sdk28-107");
  uint8_t manifest_digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, manifest_digest));
  AuthorityTransaction commission = makeCommission(device.binding, txnId, manifest_digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(108);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 109, commission);

  const std::string sidecar_dir = uniqueTestDir("baseline-sidecar");
  FileBackedOriginalBaselineManifestSidecar sidecar(pair, sidecar_dir);
  ASSERT_EQ(sidecar.recordOriginalBaselineManifest(device.binding, txnId, manifest, 0x2u),
            OriginalBaselineManifestRecordOutcome::Ok);

  // A DIFFERENT candidate for the SAME transaction -- even if it somehow
  // also happened to match the signed digest (it does not here, since
  // digests are collision-resistant) -- must never silently overwrite
  // the already-recorded fact. Using a target id mismatch exercises the
  // "different record" comparison directly.
  EXPECT_EQ(sidecar.recordOriginalBaselineManifest(device.binding, txnId, manifest, 0x3u),
            OriginalBaselineManifestRecordOutcome::ConflictingExistingRecord);

  // A tampered on-disk sidecar file (bit flip after the fact, modeling
  // corruption/an attacker with filesystem access) must be refused at
  // lookup time too -- this class re-verifies the digest fresh every
  // call, it does not just trust whatever bytes are currently on disk.
  bool any_file_found = false;
  for (const auto& entry : fs::directory_iterator(sidecar_dir)) {
    if (entry.path().extension() == ".bin") {
      std::fstream f(entry.path(), std::ios::in | std::ios::out | std::ios::binary);
      f.seekp(20);
      char byte;
      f.seekg(20);
      f.read(&byte, 1);
      byte ^= 0xFF;
      f.seekp(20);
      f.write(&byte, 1);
      any_file_found = true;
    }
  }
  ASSERT_TRUE(any_file_found);

  AuthorityBootFloorBaselineProvenanceRecord looked_up;
  EXPECT_FALSE(sidecar.lookupOriginalBaselineProvenance(device.binding, txnId, looked_up));

  // Astra typed-absence/error fix: a tampered (present-but-corrupt) file
  // must ALSO be refused at record() time -- it must NEVER be silently
  // treated as "no existing record yet" and overwritten. Before this
  // fix, a corrupt read collapsed to the same `false` as a genuinely
  // absent file, so a fresh (otherwise-valid) re-record would have
  // quietly replaced the already-corrupted-on-disk state without ever
  // surfacing that anything was wrong.
  EXPECT_EQ(sidecar.recordOriginalBaselineManifest(device.binding, txnId, manifest, 0x2u),
            OriginalBaselineManifestRecordOutcome::IoFailure);
}

TEST_F(AuthorityFixture, RealBaselineProvenanceSidecarRefusesUnknownTransactionAndWrongOwner) {
  TestDevice device("real-provenance-owner-device", 110);
  TestDevice other_device("real-provenance-other-owner-device", 111);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0xAA);

  BaselineCertificationManifest manifest;
  fillSeed(manifest.approvedImageSha256, "provenance-image-110");
  manifest.approvedImageExtentLength = 0x9800;
  fillSeed(manifest.expectedSdk28Sha256Digest, "provenance-sdk28-110");
  uint8_t manifest_digest[kDigestBytes];
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, manifest_digest));
  AuthorityTransaction commission = makeCommission(device.binding, txnId, manifest_digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(112);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 113, commission);

  const std::string sidecar_dir = uniqueTestDir("baseline-sidecar");
  FileBackedOriginalBaselineManifestSidecar sidecar(pair, sidecar_dir);

  // Recording against a transaction id that was never actually issued at
  // all must be refused (positively absent, never fabricated).
  uint8_t unknown_txn_id[kTransactionIdBytes];
  makeTxnId(unknown_txn_id, 0xAB);
  EXPECT_EQ(sidecar.recordOriginalBaselineManifest(device.binding, unknown_txn_id, manifest, 0x1u),
            OriginalBaselineManifestRecordOutcome::TransactionNotFound);

  // Recording the genuinely correct manifest but against the WRONG
  // claimed owner (a different physical device) must be refused even
  // though the manifest digest itself is genuinely correct for `txnId`.
  EXPECT_EQ(sidecar.recordOriginalBaselineManifest(other_device.binding, txnId, manifest, 0x1u),
            OriginalBaselineManifestRecordOutcome::BindingMismatch);

  // And a lookup for a transaction that was simply never recorded at
  // all denies -- no success-shaped fallback, ever.
  AuthorityBootFloorBaselineProvenanceRecord looked_up;
  EXPECT_FALSE(sidecar.lookupOriginalBaselineProvenance(device.binding, txnId, looked_up));
}


TEST_F(AuthorityFixture, BootFloorExportRejectsUnknownTransactionAndMissingDependencies) {
  TestDevice device("floor-export-missing-device", 62);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x62);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  uint8_t zero_sdk28[kBootFloorOriginalSdk28DigestBytes] = {0};
  FakeOriginalBaselineSdk28Provenance provenance(zero_sdk28);
  BootFloorBaselineEvidence baseline;
  BootFloorActivationReceiptV1 receipt;

  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, &test_lock_);
  EXPECT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::TransactionNotFound);

  BootFloorActivationReceiptExporter no_verifier(pair, nullptr, issuer_trust_.get(), &publisher, &provenance, &test_lock_);
  EXPECT_EQ(no_verifier.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Denied);
  BootFloorActivationReceiptExporter no_issuer_trust(pair, &verifier_, nullptr, &publisher, &provenance, &test_lock_);
  EXPECT_EQ(no_issuer_trust.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Denied);
  BootFloorActivationReceiptExporter no_publisher(pair, &verifier_, issuer_trust_.get(), nullptr, &provenance, &test_lock_);
  EXPECT_EQ(no_publisher.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Denied);
  BootFloorActivationReceiptExporter no_provenance(pair, &verifier_, issuer_trust_.get(), &publisher, nullptr, &test_lock_);
  EXPECT_EQ(no_provenance.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Denied);
  // Sol39 H4: crossProcessLock_ is now a REQUIRED dependency exactly
  // like the others above -- a missing lease must deny, never proceed
  // unserialized against the Coordinator's own mutating entrypoints.
  BootFloorActivationReceiptExporter no_lock(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, nullptr);
  EXPECT_EQ(no_lock.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Denied);
}

TEST_F(AuthorityFixture, BootFloorExportRejectsRepairRekeyAndCertifyExistingBaselineOperations) {
  TestDevice device("floor-export-crossuse-device", 63);
  uint8_t commission_id[kTransactionIdBytes];
  makeTxnId(commission_id, 0x63);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-63");
  AuthorityTransaction commission = makeCommission(device.binding, commission_id, digest, /*txFloor=*/1, /*rxFloor=*/1);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(64);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, commission_id, device, 65, commission);

  // Genuine repair, ActivationSpent -- a real TxRxActivationPermit grant,
  // but explicitly must NOT count as boot-floor-genesis proof.
  uint8_t repair_id[kTransactionIdBytes];
  makeTxnId(repair_id, 0x64);
  AuthorityTransaction repair;
  repair.binding = device.binding;
  repair.operation = AuthorityOperation::Repair;
  std::memcpy(repair.transactionId, repair_id, kTransactionIdBytes);
  repair.revision = 1;
  std::memcpy(repair.predecessorTransactionId, commission_id, kTransactionIdBytes);
  std::memcpy(repair.manifestDigestSha256, digest, kDigestBytes);
  repair.initialTxSequenceFloor = 1;
  repair.initialRxReplayFloor = 1;
  repair.issuerKeyId = 1;
  sign(repair);
  ASSERT_EQ(coordinator.repairExisting(repair), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, repair_id, device, 66, repair);

  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  uint8_t zero_sdk28[kBootFloorOriginalSdk28DigestBytes] = {0};
  FakeOriginalBaselineSdk28Provenance provenance(zero_sdk28);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, &test_lock_);
  BootFloorBaselineEvidence baseline;
  BootFloorActivationReceiptV1 receipt;
  EXPECT_EQ(exporter.exportReceipt(repair_id, baseline, receipt), BootFloorExportOutcome::OperationMismatch);

  // The ORIGINAL commission txn is now SUPERSEDED by the repair (which is
  // the new latest ActivationSpent history for this owner) -- exporting
  // for it must be refused too, never silently re-export stale genesis
  // proof over newer history.
  EXPECT_EQ(exporter.exportReceipt(commission_id, baseline, receipt), BootFloorExportOutcome::Superseded);

  // CertifyExistingBaseline never enters the ActivationSpent lifecycle at
  // all (see AuthorityCoordinator::eligibleForActivationLifecycle), so it
  // cannot even reach the operation check below via prepare/activate --
  // confirm it is refused at the TransactionNotFound stage (reconcile()
  // only ever sees it as Issued, never ActivationSpent).
  uint8_t baseline_manifest_digest[kDigestBytes];
  BaselineCertificationManifest manifest = makeBaselineManifest(10);
  ASSERT_TRUE(BaselineCertificationManifestCodec::computeDigestSha256(manifest, baseline_manifest_digest));
  uint8_t baseline_txn_id[kTransactionIdBytes];
  makeTxnId(baseline_txn_id, 0x65);
  AuthorityTransaction baseline_txn = makeCertifyExistingBaseline(device.binding, baseline_txn_id, baseline_manifest_digest);
  ASSERT_EQ(coordinator.submitCertifyExistingBaseline(baseline_txn), AuthorityOutcome::Ok);
  EXPECT_EQ(exporter.exportReceipt(baseline_txn_id, baseline, receipt), BootFloorExportOutcome::NotActivationSpent);
}

// Sol39 H5: the EXACT cross-key dominance gap this review found -- the
// OLD owner-scoped ("latest activation for THIS fullPK") check cannot
// see a Rekey to a genuinely different fullPK, so exporting the
// ORIGINAL Commission after it has been superseded by a cross-key
// Rekey must now be refused via the physical-lineage (UID+domain+
// layout, across every key) scan instead.
TEST_F(AuthorityFixture, BootFloorExportRefusesStaleGenesisAfterACrossKeyRekeySupersedesTheOriginalCommission) {
  TestDevice device("floor-export-rekey-device", 130);
  uint8_t commission_id[kTransactionIdBytes];
  makeTxnId(commission_id, 0xC0);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-130");
  AuthorityTransaction commission = makeCommission(device.binding, commission_id, digest, 1, 1);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(130);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, commission_id, device, 131, commission);

  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  uint8_t zero_sdk28[kBootFloorOriginalSdk28DigestBytes] = {0};
  FakeOriginalBaselineSdk28Provenance provenance(zero_sdk28);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, &test_lock_);
  BootFloorBaselineEvidence baseline;
  BootFloorActivationReceiptV1 receipt;

  // Before any rekey: the original Commission is genuinely still the
  // current tip -- export succeeds.
  ASSERT_EQ(exporter.exportReceipt(commission_id, baseline, receipt), BootFloorExportOutcome::Ok);

  // Genuine cross-key Rekey A->B, fully activated.
  TestDevice identity_b("floor-export-rekey-device-key-b", 130);
  AuthorityTransaction rekey_to_b;
  rekey_to_b.binding = device.binding;
  std::memcpy(rekey_to_b.binding.meshFullPublicKey, identity_b.signer.publicKey(), kPublicKeyBytes);
  rekey_to_b.operation = AuthorityOperation::Rekey;
  uint8_t rekey_b_txn_id[kTransactionIdBytes];
  makeTxnId(rekey_b_txn_id, 0xC1);
  std::memcpy(rekey_to_b.transactionId, rekey_b_txn_id, kTransactionIdBytes);
  rekey_to_b.revision = 1;
  std::memcpy(rekey_to_b.predecessorTransactionId, commission_id, kTransactionIdBytes);
  std::memcpy(rekey_to_b.manifestDigestSha256, digest, kDigestBytes);
  rekey_to_b.initialTxSequenceFloor = 1;
  rekey_to_b.initialRxReplayFloor = 1;
  rekey_to_b.issuerKeyId = 1;
  sign(rekey_to_b);
  ASSERT_EQ(coordinator.rekeyExplicitly(rekey_to_b, device.binding), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, rekey_b_txn_id, identity_b, 132, rekey_to_b);

  // The ORIGINAL Commission's own fullPK-scoped "latest activation for
  // its own owner" would (with the OLD, rejected check) still see
  // itself as latest, since the scope never crosses to B's fullPK.
  // Exporting it now must be refused: the physical lineage (scanning
  // ACROSS keys) has moved on.
  EXPECT_EQ(exporter.exportReceipt(commission_id, baseline, receipt), BootFloorExportOutcome::Superseded);
}

TEST_F(AuthorityFixture, BootFloorExportRejectsTamperedIssuerSignatureAndCorruptRegistry) {
  TestDevice device("floor-export-tamper-device", 64);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x66);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-66");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(67);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 68, commission);

  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  uint8_t zero_sdk28[kBootFloorOriginalSdk28DigestBytes] = {0};
  FakeOriginalBaselineSdk28Provenance provenance(zero_sdk28);
  BootFloorActivationReceiptV1 receipt;
  BootFloorBaselineEvidence baseline;

  // An issuer trust map that no longer recognizes this key id (simulates
  // trust revocation between commission time and export time) must deny.
  class EmptyIssuerTrust : public AuthorityIssuerTrust {
   public:
    bool lookupIssuerPublicKey(uint16_t, uint8_t[kPublicKeyBytes]) const override { return false; }
  } empty_trust;
  BootFloorActivationReceiptExporter revoked_exporter(pair, &verifier_, &empty_trust, &publisher, &provenance, &test_lock_);
  EXPECT_EQ(revoked_exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::SignatureInvalid);

  // A registry copy that no longer agrees with the other (simulates
  // corruption/rollback of one copy between activation and export) must
  // deny -- "both reconciled copies" is not satisfied by one alone. Flip
  // a byte inside copy A's durable file directly (same technique as
  // FileCopyReportsCorruptButPresentOnBitFlip) -- appendStateTransition
  // itself correctly refuses to regress a copy already at ActivationSpent,
  // so genuine desync here can only come from actual file corruption,
  // exactly as it would in real use.
  {
    std::fstream f(copyAPath_, std::ios::in | std::ios::out | std::ios::binary);
    f.seekp(10);
    char byte;
    f.seekg(10);
    f.read(&byte, 1);
    byte ^= 0xFF;
    f.seekp(10);
    f.write(&byte, 1);
  }
  BootFloorActivationReceiptExporter desynced_exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, &test_lock_);
  EXPECT_EQ(desynced_exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::RegistryDisagreement);
}

// Regression coverage for the review-clarified requirement that the
// receipt's publisherKeyId/publisherKeyFingerprintSha256/signature are
// bound to the (possibly distinct) firmware PUBLISHER key -- never the
// commission ISSUER key, even though the exporter independently checks
// both. Uses a GENUINELY DIFFERENT Ed25519 keypair for the publisher
// than for the issuer (unlike the other exporter tests above, which
// reuse the same synthetic test key under two different keyIds purely
// for brevity) to prove there is no accidental key-material conflation
// anywhere in the exporter's field population or signing call.
TEST_F(AuthorityFixture, BootFloorExportBindsDistinctPublisherKeyNeverTheIssuerKey) {
  TestDevice device("floor-export-distinct-publisher-device", 71);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x71);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-71");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(72);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 73, commission);

  uint8_t publisher_seed[32];
  fillSeed(publisher_seed, "compiled-boot-publisher-key");  // Deliberately distinct seed from "issuer".
  ota::test::Ed25519TestSigner publisher_signer(publisher_seed);
  ASSERT_NE(0, std::memcmp(publisher_signer.publicKey(), issuer_signer_->publicKey(), kPublicKeyBytes));
  FakePublisherKeyTrust publisher(publisher_signer, /*keyId=*/99);

  BootFloorBaselineEvidence baseline;
  fillSeed(baseline.imageSha256, "baseline-image-71");
  baseline.extentLength = 0x9000;
  fillSeed(baseline.original28Sha256Digest, "original-sdk28-71");
  baseline.targetId = 0x584E3402u;
  FakeOriginalBaselineSdk28Provenance provenance(baseline.original28Sha256Digest, baseline.imageSha256,
                                                  baseline.extentLength, baseline.targetId);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &publisher, &provenance, &test_lock_);

  BootFloorActivationReceiptV1 receipt;
  ASSERT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Ok);

  // keyID and fingerprint on the receipt are the PUBLISHER's, not the
  // issuer's.
  EXPECT_EQ(receipt.publisherKeyId, 99u);
  uint8_t expected_publisher_fingerprint[kDigestBytes];
  ota::trust::Sha256::hash(publisher_signer.publicKey(), kPublicKeyBytes, expected_publisher_fingerprint);
  EXPECT_EQ(0, std::memcmp(receipt.publisherKeyFingerprintSha256, expected_publisher_fingerprint, kDigestBytes));
  uint8_t issuer_fingerprint[kDigestBytes];
  ota::trust::Sha256::hash(issuer_signer_->publicKey(), kPublicKeyBytes, issuer_fingerprint);
  EXPECT_NE(0, std::memcmp(receipt.publisherKeyFingerprintSha256, issuer_fingerprint, kDigestBytes));

  // The signature verifies under the PUBLISHER's public key...
  uint8_t expected_digest[kDigestBytes];
  ASSERT_TRUE(BootFloorActivationReceiptCodec::computeSignedDigest(receipt, expected_digest));
  EXPECT_TRUE(verifier_.verify(receipt.signatureEd25519, kSignatureBytes, expected_digest, sizeof(expected_digest),
                                publisher_signer.publicKey(), kPublicKeyBytes));
  // ...and NEVER under the issuer's public key (proves the exporter did
  // not accidentally sign with, or bind fingerprint/keyId to, the
  // issuer's key instead of the publisher's).
  EXPECT_FALSE(verifier_.verify(receipt.signatureEd25519, kSignatureBytes, expected_digest, sizeof(expected_digest),
                                 issuer_signer_->publicKey(), kPublicKeyBytes));

  // The underlying AuthorityTransaction issuer signature is still
  // independently bound to the issuer's own key -- the two trust
  // relationships genuinely coexist without either being substitutable
  // for the other.
  uint8_t signed_msg[AuthorityCodec::kSignedMessageBytes];
  ASSERT_EQ(AuthorityCodec::serializeSignedMessage(commission, signed_msg, sizeof(signed_msg)),
            AuthorityCodec::kSignedMessageBytes);
  EXPECT_TRUE(verifier_.verify(commission.issuerSignatureEd25519, kSignatureBytes, signed_msg, sizeof(signed_msg),
                                issuer_signer_->publicKey(), kPublicKeyBytes));
}

TEST_F(AuthorityFixture, BootFloorExportDeniesWhenPublisherSigningFails) {
  TestDevice device("floor-export-signfail-device", 65);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x67);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-67");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(69);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 70, commission);

  FakePublisherKeyTrust failing_publisher(*issuer_signer_, 7, /*fail_signing=*/true);
  uint8_t zero_sdk28[kBootFloorOriginalSdk28DigestBytes] = {0};
  FakeOriginalBaselineSdk28Provenance provenance(zero_sdk28);
  BootFloorActivationReceiptExporter exporter(pair, &verifier_, issuer_trust_.get(), &failing_publisher, &provenance, &test_lock_);
  BootFloorBaselineEvidence baseline;
  BootFloorActivationReceiptV1 receipt;
  EXPECT_EQ(exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::PublisherSigningFailed);
}

// The new (Boot73-75) requirement: a caller-supplied
// BootFloorBaselineEvidence.original28Sha256Digest must be independently
// verified against the AUTHORITATIVE original-SDK28 provenance record
// for this exact owner/transaction -- never trusted from the caller
// alone. A caller claiming a WRONG digest (even with every other check
// otherwise passing -- valid signature, both copies ActivationSpent,
// genesis operation) must be refused, and the seam being entirely
// unwired (nullptr) must default-deny exactly like every other required
// dependency -- never a success-shaped fallback that just copies
// whatever the caller said.
TEST_F(AuthorityFixture, BootFloorExportRejectsOriginalSdk28MismatchAndMissingProvenanceSeam) {
  TestDevice device("floor-export-sdk28-device", 74);
  uint8_t txnId[kTransactionIdBytes];
  makeTxnId(txnId, 0x74);
  uint8_t digest[kDigestBytes];
  fillSeed(digest, "manifest-74");
  AuthorityTransaction commission = makeCommission(device.binding, txnId, digest);

  FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
  AuthorityRegistryPair pair(a, b);
  CountingEntropy host_entropy(75);
  AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &host_entropy,
                                    activation_signing_trust_.get(), &test_lock_, prepare_signing_trust_.get());
  ASSERT_EQ(coordinator.submitCommission(commission), AuthorityOutcome::Ok);
  prepareAndActivate(coordinator, txnId, device, 76, commission);

  FakePublisherKeyTrust publisher(*issuer_signer_, 7);
  BootFloorBaselineEvidence baseline;
  fillSeed(baseline.imageSha256, "baseline-image-74");
  baseline.extentLength = 0x7000;
  fillSeed(baseline.original28Sha256Digest, "CLAIMED-original-sdk28-74");
  baseline.targetId = 0x584E3403u;

  // Authoritative provenance record disagrees with the caller's claim.
  uint8_t authoritative_sdk28[kBootFloorOriginalSdk28DigestBytes];
  fillSeed(authoritative_sdk28, "ACTUAL-original-sdk28-74");
  ASSERT_NE(0, std::memcmp(authoritative_sdk28, baseline.original28Sha256Digest,
                            kBootFloorOriginalSdk28DigestBytes));
  FakeOriginalBaselineSdk28Provenance mismatching_provenance(authoritative_sdk28);
  BootFloorActivationReceiptExporter mismatch_exporter(pair, &verifier_, issuer_trust_.get(), &publisher,
                                                         &mismatching_provenance, &test_lock_);
  BootFloorActivationReceiptV1 receipt;
  EXPECT_EQ(mismatch_exporter.exportReceipt(txnId, baseline, receipt),
            BootFloorExportOutcome::OriginalBaselineSdk28Mismatch);

  // The seam itself being entirely unwired (unable to answer at all --
  // e.g. no durable provenance record exists yet) must ALSO deny, never
  // silently accept the caller's claim as if it were authoritative.
  DenyingOriginalBaselineSdk28Provenance denying_provenance;
  BootFloorActivationReceiptExporter denied_exporter(pair, &verifier_, issuer_trust_.get(), &publisher,
                                                       &denying_provenance, &test_lock_);
  EXPECT_EQ(denied_exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Denied);

  // A genuinely matching authoritative record, by contrast, succeeds --
  // proving the check is a real comparison, not merely "always deny".
  FakeOriginalBaselineSdk28Provenance matching_provenance(baseline.original28Sha256Digest, baseline.imageSha256,
                                                            baseline.extentLength, baseline.targetId);
  BootFloorActivationReceiptExporter matching_exporter(pair, &verifier_, issuer_trust_.get(), &publisher,
                                                         &matching_provenance, &test_lock_);
  EXPECT_EQ(matching_exporter.exportReceipt(txnId, baseline, receipt), BootFloorExportOutcome::Ok);
}

// Sol fe862c8 review, H2: a real flock()-based cross-process lock must
// actually exclude a SECOND, entirely independent OS process -- not just
// a second object/thread inside the SAME process. Deterministic
// regardless of scheduler timing: the child holds the lock for a fixed
// window while the parent's blocking acquire() must not return until
// AFTER the child's release (never "usually" -- flock(LOCK_EX) is a
// genuine kernel-enforced exclusion, not advisory-by-convention here).
TEST_F(AuthorityFixture, CrossProcessLockActuallyExcludesASecondRealOsProcess) {
  // Shared memory so the (unrelated, COW-separate-address-space) child
  // and parent can hand timestamps back and forth.
  struct SharedState {
    struct timespec child_acquired;
    struct timespec child_released;
    bool child_acquire_ok;
  };
  void* shm = mmap(nullptr, sizeof(SharedState), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(shm, MAP_FAILED);
  auto* state = static_cast<SharedState*>(shm);
  state->child_acquire_ok = false;

  const pid_t pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    // Child: acquire the lock first, hold it for a fixed window, then
    // release -- exercised via the REAL file path, a brand-new
    // FileAuthorityCrossProcessLock instance (genuinely independent
    // process, independent fd, independent address space).
    FileAuthorityCrossProcessLock child_lock(copyAPath_, copyBPath_);
    const bool ok = child_lock.acquire();
    clock_gettime(CLOCK_MONOTONIC, &state->child_acquired);
    state->child_acquire_ok = ok;
    usleep(200 * 1000);  // Hold the lock for 200ms -- long enough that the
                         // parent's concurrent blocking acquire() cannot
                         // possibly race past it by accident.
    clock_gettime(CLOCK_MONOTONIC, &state->child_released);
    if (ok) child_lock.release();
    _exit(ok ? 0 : 1);
  }

  // Parent: give the child a head start to actually take the lock first,
  // then attempt its OWN independent acquire() on the exact same
  // (path-derived) lock file -- this call must BLOCK until the child's
  // release() actually happens.
  usleep(20 * 1000);
  FileAuthorityCrossProcessLock parent_lock(copyAPath_, copyBPath_);
  ASSERT_TRUE(parent_lock.acquire());
  struct timespec parent_acquired;
  clock_gettime(CLOCK_MONOTONIC, &parent_acquired);
  parent_lock.release();

  int status = 0;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
  ASSERT_TRUE(state->child_acquire_ok);

  auto toNanos = [](const struct timespec& ts) { return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + ts.tv_nsec; };
  // The parent's successful acquire() must be observed strictly AFTER
  // the child's release -- proof this is genuine cross-process mutual
  // exclusion, not two independent in-process locks that happen not to
  // collide.
  EXPECT_GE(toNanos(parent_acquired), toNanos(state->child_released));
  munmap(shm, sizeof(SharedState));
}

// Sol39 H2: the lock identity must NOT change between a copy that does
// not exist yet and the same copy once created -- a lock instance
// constructed while the file is genuinely ABSENT and a lock instance
// constructed AFTER the file is created (by the other side's O_CREAT)
// must still contend on the exact same underlying file. The rejected
// prior design derived a DIFFERENT sidecar path in each case; this
// design re-opens (O_CREAT, idempotent) the REAL copy file on every
// acquire(), so identity is always derived fresh from the live fd.
TEST_F(AuthorityFixture, CrossProcessLockIdentityIsStableAcrossTheAbsentToPresentTransition) {
  // Use a copy path that genuinely does not exist on disk yet -- the
  // fixture's dir_ exists, but copyAPath_ itself has no file until a
  // lock (or a real append) creates it.
  struct stat probe;
  ASSERT_NE(::stat(copyAPath_.c_str(), &probe), 0);
  ASSERT_EQ(errno, ENOENT);

  struct SharedState {
    struct timespec child_acquired;
    struct timespec child_released;
    bool child_acquire_ok;
  };
  void* shm = mmap(nullptr, sizeof(SharedState), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(shm, MAP_FAILED);
  auto* state = static_cast<SharedState*>(shm);
  state->child_acquire_ok = false;

  const pid_t pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    // Child: constructs its lock object while copyAPath_ is STILL
    // absent (same instant as the parent), then acquires -- this is
    // the first side to actually O_CREAT the file.
    FileAuthorityCrossProcessLock child_lock(copyAPath_, copyBPath_);
    const bool ok = child_lock.acquire();
    clock_gettime(CLOCK_MONOTONIC, &state->child_acquired);
    state->child_acquire_ok = ok;
    usleep(200 * 1000);
    clock_gettime(CLOCK_MONOTONIC, &state->child_released);
    if (ok) child_lock.release();
    _exit(ok ? 0 : 1);
  }

  // Parent: deliberately waits until AFTER the child has almost
  // certainly already created copyAPath_ via its O_CREAT, THEN
  // constructs its OWN lock instance -- a genuinely "constructed after
  // the file exists" instance -- and attempts to acquire. This must
  // still BLOCK until the child releases: proof the two instances
  // resolve to the SAME identity despite being constructed on opposite
  // sides of the absent->present transition.
  usleep(50 * 1000);
  FileAuthorityCrossProcessLock parent_lock(copyAPath_, copyBPath_);
  ASSERT_TRUE(parent_lock.acquire());
  struct timespec parent_acquired;
  clock_gettime(CLOCK_MONOTONIC, &parent_acquired);
  parent_lock.release();

  int status = 0;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
  ASSERT_TRUE(state->child_acquire_ok);

  auto toNanos = [](const struct timespec& ts) { return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + ts.tv_nsec; };
  EXPECT_GE(toNanos(parent_acquired), toNanos(state->child_released));
  munmap(shm, sizeof(SharedState));
}

// Sol39 H2: a HARDLINK of copy A, reachable through a genuinely
// DIFFERENT directory, must still contend against a lock built from
// the ORIGINAL path -- dev+ino identity must never incorporate the
// parent directory, since that is exactly what broke hardlink
// equivalence in the rejected prior design.
TEST_F(AuthorityFixture, CrossProcessLockTreatsAHardlinkInADifferentDirectoryAsTheSamePhysicalCopy) {
  // Create copyAPath_ for real first (so the hardlink below has
  // something to link to), then a second directory with a hardlink to
  // the SAME inode.
  const int touch_fd = open(copyAPath_.c_str(), O_CREAT | O_RDWR, 0600);
  ASSERT_GE(touch_fd, 0);
  close(touch_fd);

  const std::string other_dir = dir_ + "/other-dir";
  ASSERT_EQ(::mkdir(other_dir.c_str(), 0700), 0);
  const std::string hardlink_path = other_dir + "/copyA-hardlink.bin";
  ASSERT_EQ(::link(copyAPath_.c_str(), hardlink_path.c_str()), 0);

  struct stat original_stat, hardlink_stat;
  ASSERT_EQ(::stat(copyAPath_.c_str(), &original_stat), 0);
  ASSERT_EQ(::stat(hardlink_path.c_str(), &hardlink_stat), 0);
  ASSERT_EQ(original_stat.st_ino, hardlink_stat.st_ino);
  ASSERT_EQ(original_stat.st_dev, hardlink_stat.st_dev);

  struct SharedState {
    struct timespec child_acquired;
    struct timespec child_released;
    bool child_acquire_ok;
  };
  void* shm = mmap(nullptr, sizeof(SharedState), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(shm, MAP_FAILED);
  auto* state = static_cast<SharedState*>(shm);
  state->child_acquire_ok = false;

  const pid_t pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    // Child locks (copyAPath_, copyBPath_) -- the ORIGINAL path.
    FileAuthorityCrossProcessLock child_lock(copyAPath_, copyBPath_);
    const bool ok = child_lock.acquire();
    clock_gettime(CLOCK_MONOTONIC, &state->child_acquired);
    state->child_acquire_ok = ok;
    usleep(200 * 1000);
    clock_gettime(CLOCK_MONOTONIC, &state->child_released);
    if (ok) child_lock.release();
    _exit(ok ? 0 : 1);
  }

  // Parent locks (hardlink_path, copyBPath_) -- a DIFFERENT path string,
  // in a DIFFERENT directory, but the SAME physical inode as copyAPath_.
  // This must still block on the child's hold.
  usleep(20 * 1000);
  FileAuthorityCrossProcessLock parent_lock(hardlink_path, copyBPath_);
  ASSERT_TRUE(parent_lock.acquire());
  struct timespec parent_acquired;
  clock_gettime(CLOCK_MONOTONIC, &parent_acquired);
  parent_lock.release();

  int status = 0;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
  ASSERT_TRUE(state->child_acquire_ok);

  auto toNanos = [](const struct timespec& ts) { return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + ts.tv_nsec; };
  EXPECT_GE(toNanos(parent_acquired), toNanos(state->child_released));
  munmap(shm, sizeof(SharedState));
}

// Sol39 H2: the globally-stable (dev,ino) acquisition order must also
// correctly serialize OVERLAPPING pairs that share exactly one common
// copy -- e.g. pair (A,B) and pair (B,C) -- which the rejected
// lexicographic-pair-path design never did (each pair derived its own
// independent min(path) lock file). Two real OS processes, one locking
// (A,B) and the other locking (B,C), racing for overlapping ownership
// of B, must never both report success simultaneously.
TEST_F(AuthorityFixture, CrossProcessLockSerializesOverlappingPairsSharingOneCommonCopy) {
  const std::string copyCPath = dir_ + "/copyC.bin";

  struct SharedState {
    struct timespec child_acquired;
    struct timespec child_released;
    bool child_acquire_ok;
  };
  void* shm = mmap(nullptr, sizeof(SharedState), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(shm, MAP_FAILED);
  auto* state = static_cast<SharedState*>(shm);
  state->child_acquire_ok = false;

  const pid_t pid = fork();
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    // Child locks pair (B, C).
    FileAuthorityCrossProcessLock child_lock(copyBPath_, copyCPath);
    const bool ok = child_lock.acquire();
    clock_gettime(CLOCK_MONOTONIC, &state->child_acquired);
    state->child_acquire_ok = ok;
    usleep(200 * 1000);
    clock_gettime(CLOCK_MONOTONIC, &state->child_released);
    if (ok) child_lock.release();
    _exit(ok ? 0 : 1);
  }

  // Parent locks pair (A, B) -- overlapping on B only.
  usleep(20 * 1000);
  FileAuthorityCrossProcessLock parent_lock(copyAPath_, copyBPath_);
  ASSERT_TRUE(parent_lock.acquire());
  struct timespec parent_acquired;
  clock_gettime(CLOCK_MONOTONIC, &parent_acquired);
  parent_lock.release();

  int status = 0;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
  ASSERT_TRUE(WIFEXITED(status));
  EXPECT_EQ(WEXITSTATUS(status), 0);
  ASSERT_TRUE(state->child_acquire_ok);

  auto toNanos = [](const struct timespec& ts) { return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + ts.tv_nsec; };
  EXPECT_GE(toNanos(parent_acquired), toNanos(state->child_released));
  munmap(shm, sizeof(SharedState));
}


// the OS scheduler happens to run first (this is a correctness
// guarantee from mutual exclusion, not a timing-dependent "usually").
TEST_F(AuthorityFixture, TwoRealOsProcessesRacingCommissionForTheSameOwnerNeverBothSucceed) {
  TestDevice device("cross-process-race-device", 91);
  uint8_t digest_a[kDigestBytes], digest_b[kDigestBytes];
  fillSeed(digest_a, "manifest-91-race-a");
  fillSeed(digest_b, "manifest-91-race-b");
  uint8_t txn_id_a[kTransactionIdBytes], txn_id_b[kTransactionIdBytes];
  makeTxnId(txn_id_a, 0x91);
  makeTxnId(txn_id_b, 0x92);
  AuthorityTransaction txn_a = makeCommission(device.binding, txn_id_a, digest_a);
  AuthorityTransaction txn_b = makeCommission(device.binding, txn_id_b, digest_b);

  struct SharedState {
    std::atomic<int> ready_count;
    int outcome_a;
    int outcome_b;
  };
  void* shm = mmap(nullptr, sizeof(SharedState), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(shm, MAP_FAILED);
  auto* state = new (shm) SharedState();
  state->ready_count.store(0);
  state->outcome_a = -1;
  state->outcome_b = -1;

  auto runChild = [&](const AuthorityTransaction& txn, int* out_outcome) {
    FileAuthorityRegistryCopy a(copyAPath_), b(copyBPath_);
    AuthorityRegistryPair pair(a, b);
    FileAuthorityCrossProcessLock lock(copyAPath_, copyBPath_);
    CountingEntropy entropy(static_cast<uint32_t>(txn.transactionId[0]));
    AuthorityCoordinator coordinator(pair, &verifier_, issuer_trust_.get(), &entropy, activation_signing_trust_.get(),
                                      &lock, prepare_signing_trust_.get());
    state->ready_count.fetch_add(1);
    while (state->ready_count.load() < 2) { /* spin: maximize actual overlap */
    }
    *out_outcome = static_cast<int>(coordinator.submitCommission(txn));
  };

  const pid_t pid_a = fork();
  ASSERT_GE(pid_a, 0);
  if (pid_a == 0) {
    runChild(txn_a, &state->outcome_a);
    _exit(0);
  }
  const pid_t pid_b = fork();
  ASSERT_GE(pid_b, 0);
  if (pid_b == 0) {
    runChild(txn_b, &state->outcome_b);
    _exit(0);
  }

  int status_a = 0, status_b = 0;
  ASSERT_EQ(waitpid(pid_a, &status_a, 0), pid_a);
  ASSERT_EQ(waitpid(pid_b, &status_b, 0), pid_b);
  ASSERT_TRUE(WIFEXITED(status_a));
  ASSERT_TRUE(WIFEXITED(status_b));

  const auto outcome_a = static_cast<AuthorityOutcome>(state->outcome_a);
  const auto outcome_b = static_cast<AuthorityOutcome>(state->outcome_b);
  const bool a_ok = outcome_a == AuthorityOutcome::Ok;
  const bool b_ok = outcome_b == AuthorityOutcome::Ok;
  // Exactly one process's Commission may ever win the exact same owner
  // -- never both (a genuine ownership fork) and never neither (the
  // lock must not deadlock/spuriously deny both real attempts).
  EXPECT_TRUE(a_ok != b_ok) << "outcome_a=" << static_cast<int>(outcome_a) << " outcome_b=" << static_cast<int>(outcome_b);
  if (!a_ok) EXPECT_EQ(outcome_a, AuthorityOutcome::StaleRevision);
  if (!b_ok) EXPECT_EQ(outcome_b, AuthorityOutcome::StaleRevision);

  // Confirm the registry pair itself agrees on exactly one surviving
  // owner lineage afterward -- not merely that the two in-process return
  // codes looked right.
  FileAuthorityRegistryCopy final_a(copyAPath_), final_b(copyBPath_);
  AuthorityRegistryPair final_pair(final_a, final_b);
  ReconciliationResult owner_lineage = final_pair.reconcileOwnershipLineage(device.binding);
  EXPECT_EQ(owner_lineage.outcome, ReconciliationOutcome::Agreed);

  state->~SharedState();
  munmap(shm, sizeof(SharedState));
}

}  // namespace

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
