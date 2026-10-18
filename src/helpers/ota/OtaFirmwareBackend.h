#pragma once

#include <atomic>
#include <cstring>
#include <helpers/ota/OtaV4Package.h>
#include <ota/storage/OtaV4Journal.h>
#include <ota/storage/OtaV4Staging.h>
#include <ota/trust/SignatureVerifier.h>

namespace mesh { namespace ota { namespace v4 {

struct RuntimeHooks {
  void* context = nullptr;
  Result (*identity)(void*, uint8_t[32]) = nullptr;
  bool (*isCurrentAdmin)(void*, const uint8_t[32]) = nullptr;
  Result (*sign)(void*, const char*, size_t, const uint8_t*, size_t, uint8_t[64]) = nullptr;
  Result (*lease)(void*, uint32_t, uint32_t, uint8_t, uint8_t, uint32_t) = nullptr;
};

class FirmwarePlatform : public Platform {
public:
  FirmwarePlatform(const Policy& policy, ::ota::platform::FlashRegion& payload,
                   ::ota::platform::FlashRegion& metadata,
                   const ::ota::trust::SignatureVerifier& signatures)
      : policy_(policy), journal_(metadata), staging_(payload), signatures_(signatures) {}
  void attach(const RuntimeHooks& hooks) { hooks_ = hooks; }
  Policy policy() const override { return policy_; }
  Result identity(uint8_t out[32]) override {
    return hooks_.identity ? hooks_.identity(hooks_.context, out) : Result::Unsupported;
  }
  bool isCurrentAdmin(const uint8_t key[32]) override {
    return key && hooks_.isCurrentAdmin && hooks_.isCurrentAdmin(hooks_.context, key);
  }
  bool verify(const uint8_t key[32], const char* domain, size_t domainSize,
              const uint8_t* message, size_t messageSize, const uint8_t signature[64]) override {
    if (!key || !signature || (!domain && domainSize) || (!message && messageSize) ||
        domainSize > 64 || messageSize > kMaxManifestBytes)
      return false;
    if (!domainSize)
      return signatures_.verify(signature, 64, message, messageSize, key, 32);
    static std::atomic_flag busy = ATOMIC_FLAG_INIT;
    if (busy.test_and_set()) return false;
    struct Unlock {
      std::atomic_flag& flag;
      ~Unlock() { flag.clear(); }
    } unlock{busy};
    static uint8_t transcript[kMaxManifestBytes + 64];
    std::memcpy(transcript, domain, domainSize);
    if (messageSize) std::memcpy(transcript + domainSize, message, messageSize);
    return signatures_.verify(signature, 64, transcript, domainSize + messageSize, key, 32);
  }
  Result sign(const char* domain, size_t domainSize, const uint8_t* message,
              size_t messageSize, uint8_t signature[64]) override {
    if (!signature || (!domain && domainSize) || (!message && messageSize) ||
        domainSize > kMaxControlBytes || messageSize > kMaxControlBytes - domainSize)
      return Result::Invalid;
    return hooks_.sign ? hooks_.sign(hooks_.context, domain, domainSize, message, messageSize,
                                    signature) : Result::Unsupported;
  }
  Result lease(uint32_t frequencyKHz, uint32_t bandwidthHz, uint8_t sf,
               uint8_t cr, uint32_t durationMs) override {
    return hooks_.lease ? hooks_.lease(hooks_.context, frequencyKHz, bandwidthHz, sf, cr,
                                      durationMs) : Result::Unsupported;
  }
  Result recover(Journal& out, uint8_t* manifest, size_t capacity, size_t& size) override {
    haveCandidate_ = false;
    const Result result = journal_.recover(out, manifest, capacity, size);
    if (result == Result::Ok && size) {
      Manifest package;
      if (package.parse(manifest, size) != Result::Ok ||
          std::memcmp(package.hash(), out.packageHash, 32) ||
          out.nextChunk > package.count()) return Result::Integrity;
      remember(out, package);
      const Result bound = prepareRecoveredStaging(package.descriptor().exactSizeBytes);
      if (bound != Result::Ok) return bound;
    } else {
      staging_.invalidate();
    }
    return result;
  }
  Result save(const Journal& next, const uint8_t* manifest, size_t size) override {
    Manifest package;
    if (size && (package.parse(manifest, size) != Result::Ok ||
        std::memcmp(package.hash(), next.packageHash, 32))) return Result::Integrity;
    const Result saved = journal_.save(next, manifest, size);
    if (saved == Result::Ok) {
      haveCandidate_ = false;
      if (size) remember(next, package);
    }
    return saved;
  }
  Result beginStaging(uint32_t rawSize) override {
    const Result allowed = mutationAllowed();
    return allowed == Result::Ok ? staging_.begin(rawSize) : allowed;
  }
  Result writeStaging(uint32_t offset, const uint8_t* data, size_t size) override {
    const Result allowed = mutationAllowed();
    if (allowed != Result::Ok) return allowed;
    const Result result = staging_.write(offset, data, size);
    storageFault_ = storageFault_ || result == Result::Io;
    return result;
  }
  Result readStaging(uint32_t offset, uint8_t* data, size_t size) override {
    const Result result = staging_.read(offset, data, size);
    storageFault_ = storageFault_ || result == Result::Io;
    return result;
  }
  Result clearStaging() override {
    const Result allowed = mutationAllowed();
    if (allowed != Result::Ok) return allowed;
    // Revoked bytes need not be physically erased; a new admitted chunk erases
    // exactly its sectors. This keeps abort bounded and personality-independent.
    staging_.invalidate();
    return Result::Ok;
  }
  Result repair(const Journal& idle) override {
    const Result allowed = mutationAllowed();
    if (allowed != Result::Ok) return allowed;
    const Result result = journal_.repair(idle);
    if (result == Result::Ok) {
      staging_.invalidate();
      storageFault_ = false;
      haveCandidate_ = false;
    }
    return result;
  }
  bool storageFaultObserved() const { return storageFault_ || journal_.faulted(); }

protected:
  void remember(const Journal& journal, const Manifest& package) {
    latest_ = journal;
    std::memcpy(canonical_, package.canonical(), sizeof(canonical_));
    std::memcpy(signer_, package.signer(), sizeof(signer_));
    haveCandidate_ = true;
  }
  virtual Result mutationAllowed() = 0;
  virtual Result prepareRecoveredStaging(uint32_t rawSize) { return staging_.begin(rawSize); }
  Result verifyRawImage(const uint8_t canonical[59], const uint8_t signature[64],
                         const uint8_t signer[32]) {
    if (!canonical || !signature || !signer || !isCurrentAdmin(signer) || !haveCandidate_ ||
        std::memcmp(canonical, canonical_, 59) || std::memcmp(signer, signer_, 32) ||
        !signatures_.verify(signature, 64, canonical, 59, signer, 32)) return Result::Denied;
    meshcore::ota::protocol::OtaDescriptor descriptor;
    using namespace meshcore::ota::protocol;
    if (decodeOtaDescriptorCanonical(canonical, 59, descriptor) != OtaDescriptorCodecResult::Ok ||
        descriptor.boardFamily != policy_.boardFamily || descriptor.boardVariant != policy_.boardVariant ||
        descriptor.role != policy_.role || descriptor.appAddress != policy_.appAddress ||
        descriptor.formatId != policy_.formatId || descriptor.keyId != policy_.keyId ||
        descriptor.algorithmId != policy_.algorithmId || !descriptor.exactSizeBytes ||
        descriptor.exactSizeBytes > policy_.maxImageBytes ||
        (descriptor.minBootloaderCapabilities & ~policy_.bootloaderCapabilities)) return Result::Denied;
    RunningEvidence running;
    const Result observed = evidence(running);
    if (observed != Result::Ok) return observed;
    if (!(running.flags & 1) || descriptor.securityCounter <= running.floor) return Result::Replay;
    const Result hashed = staging_.verifyImage(descriptor.exactSizeBytes, descriptor.sha256);
    storageFault_ = storageFault_ || hashed == Result::Io;
    return hashed;
  }
  Policy policy_;
  ::ota::storage::OtaV4Journal journal_;
  ::ota::storage::OtaV4Staging staging_;
  const ::ota::trust::SignatureVerifier& signatures_;
  RuntimeHooks hooks_;
  bool storageFault_ = false;
  Journal latest_;
  uint8_t canonical_[59] = {}, signer_[32] = {};
  bool haveCandidate_ = false;
};

class Receiver;

}}}

mesh::ota::v4::Receiver* otaBoardConfigureV4Backend(const mesh::ota::v4::RuntimeHooks& hooks);
