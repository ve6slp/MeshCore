#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <helpers/ota/OtaBlockSigning.h>
#include <helpers/ota/OtaUsbProtocol.h>
#include <helpers/ota/OtaProofScratch.h>
#include <ota/protocol/OtaDescriptor.h>
#include <ota/trust/SignatureVerifier.h>
#include <ota/runtime/OtaTrustInterfaces.h>
#include <ota/runtime/OtaInstallAttemptIdentity.h>
#include <ota/storage/OtaCandidateStore.h>

namespace mesh {
namespace ota {

class OtaLeanReceiver {
public:
  using Result = usb::UsbOtaResult;
  using AdminCheckFn = bool (*)(void*, const uint8_t[32]);
  using TerminalCheckFn = bool (*)(void*, const ::ota::storage::OtaCandidateStore::Snapshot&);
  using UnadmittedAbortFn = Result (*)(void*, const ::ota::storage::OtaCandidateStore::Snapshot&, bool);
  // Must fill `len` bytes from a hardware/CSPRNG source or return false.
  using EntropyFn = bool (*)(void*, uint8_t*, size_t);

  struct Status {
    bool valid = false;
    bool localCache = false;
    ::ota::storage::OtaCandidateStore::Phase phase = ::ota::storage::OtaCandidateStore::Phase::Idle;
    uint16_t receivedBlocks = 0;
    uint16_t totalBlocks = 0;
    uint32_t imageBytes = 0;
    uint16_t blockBytes = kOtaBlockMaxDataBytes;
    uint32_t generation = 0;
    uint32_t counter = 0;
    uint64_t transactionNonce = 0;
    uint8_t ownerPublicKey[32] = {0};
    uint8_t manifestHash[32] = {0};
    uint8_t imageHash[32] = {0};
    uint8_t beginNonce[usb::kBeginNonceBytes] = {0};
    // Candidate storage could not be read authoritatively; every other
    // field is meaningless and no candidate operation may proceed.
    bool storageUnavailable = false;
  };

  void attachTrustProvider(meshcore::ota::runtime::IOtaTrustProvider* provider) { trust_provider_ = provider; }
  void attachStagingSink(meshcore::ota::runtime::IOtaStagingSink* sink) { staging_sink_ = sink; tryResumeSink(); }
  void attachOwnerSignatureVerifier(const ::ota::trust::SignatureVerifier* verifier) { owner_signature_verifier_ = verifier; }
  void attachTerminalCheck(void* ctx, TerminalCheckFn fn) { terminal_ctx_ = ctx; terminal_check_ = fn; }
  void attachUnadmittedAbort(void* ctx, UnadmittedAbortFn fn) { unadmitted_ctx_ = ctx; unadmitted_abort_ = fn; }
  void attachEntropy(void* ctx, EntropyFn fn) { entropy_ctx_ = ctx; entropy_ = fn; }
  bool fillEntropy(uint8_t* out, size_t len) const { return entropy_ && out && entropy_(entropy_ctx_, out, len); }
  bool storageUnavailable() const { return storage_unavailable_; }
  // Authoritative reload after a storage read failure; true once state is known.
  bool reloadStorage() {
    if (!storage_unavailable_) return true;
    restore();
    if (storage_unavailable_) return false;
    tryResumeSink();
    return true;
  }

  void attachCandidateStore(::ota::storage::OtaCandidateStore* store) {
    store_ = store;
    restore();
    tryResumeSink();
  }

  void setAdminCheck(void* ctx, AdminCheckFn fn) {
    admin_ctx_ = ctx;
    admin_check_ = fn;
  }

  void setTargetPublicKey(const uint8_t key[32]) {
    if (key == nullptr) {
      have_target_public_key_ = false;
      std::memset(target_public_key_, 0, sizeof(target_public_key_));
      return;
    }
    std::memcpy(target_public_key_, key, sizeof(target_public_key_));
    have_target_public_key_ = true;
  }

  bool haveTargetPublicKey() const { return have_target_public_key_; }
  const uint8_t* targetPublicKey() const { return target_public_key_; }
  bool hasStore() const { return store_ != nullptr; }
  bool currentAdmin(const uint8_t key[32]) const { return isCurrentAdmin(key); }
  bool verifySignature(const uint8_t key[32], const uint8_t* message, size_t len, const uint8_t sig[64]) const {
    return verifyOwnerSignature(key, message, len, sig);
  }
  bool prepareReupload(const uint8_t owner[32], const uint8_t canonical[59], const uint8_t signature[64]) {
    if (!owner || !canonical || !signature || !candidate_.valid || !trust_provider_ ||
        candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Aborted ||
        !isCurrentAdmin(owner) || !verifyOwnerSignature(owner, canonical, 59, signature)) return false;
    meshcore::ota::protocol::OtaDescriptor descriptor;
    if (meshcore::ota::protocol::decodeOtaDescriptorCanonical(canonical, 59, descriptor) !=
          meshcore::ota::protocol::OtaDescriptorCodecResult::Ok ||
        !trust_provider_->verifyDescriptorPolicyOnly(descriptor) || !descriptor.exactSizeBytes ||
        descriptor.exactSizeBytes > ::ota::storage::OtaCandidateStore::kMaxBlocks * kOtaBlockMaxDataBytes) return false;
    std::memcpy(pending_owner_, owner, 32); std::memcpy(pending_canonical_, canonical, 59);
    std::memcpy(pending_signature_, signature, 64); pending_reupload_ = true;
    return true;
  }
  bool pendingReuploadStatus(const uint8_t hash[32], Status& out) const {
    if (!pending_reupload_ || candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Aborted) return false;
    uint8_t pending_hash[32]; computeOtaManifestHash(pending_canonical_, pending_hash);
    if (std::memcmp(hash, pending_hash, 32)) return false;
    out = status();
    out.localCache = false;
    std::memcpy(out.manifestHash, pending_hash, 32);
    std::memcpy(out.ownerPublicKey, pending_owner_, 32);
    out.totalBlocks = totalBlocksFor(usb::getBE32(pending_canonical_ + 9));
    out.receivedBlocks = 0;
    out.counter = usb::getBE32(pending_canonical_ + 45);
    return true;
  }
  Result activatePreparedReupload(const uint8_t owner[32], const uint8_t hash[32]) {
    if (!matchesPreparedReupload(owner, hash)) return Result::Mismatch;
    return begin(pending_owner_, pending_canonical_, pending_signature_, true, false);
  }

  // Read-back surface for an autonomous RF uploader pushing THIS node's
  // own locally-cached candidate out to remote targets: it needs the raw
  // canonical+signature bytes to (re)broadcast an Authorization frame,
  // genuine per-index "do we actually have this block" bookkeeping (never
  // claiming a block is available to send before it was durably
  // accepted), and the ability to read a block's bytes back out of flash
  // to re-sign fresh at TX time (never persisting/reusing a stored
  // per-block signature -- see OtaRfUploader.h).
  bool exportCandidateForUpload(uint8_t canonical_out[kOtaCanonicalManifestBytes],
                                uint8_t signature_out[64]) const {
    if (!candidate_.valid) return false;
    std::memcpy(canonical_out, candidate_.canonical, kOtaCanonicalManifestBytes);
    std::memcpy(signature_out, candidate_.signature, 64);
    return true;
  }

  bool isBlockReceived(uint16_t index) const {
    return candidate_.valid && store_ != nullptr && index < candidate_.totalBlocks && store_->isReceived(index);
  }

  Result readBlock(uint16_t index, uint8_t* out, size_t out_capacity, size_t& out_len) {
    out_len = 0;
    if (!candidate_.valid || staging_sink_ == nullptr || index >= candidate_.totalBlocks) return Result::NotFound;
    if (!store_->isReceived(index)) return Result::NotFound;
    const uint32_t offset = static_cast<uint32_t>(index) * kOtaBlockMaxDataBytes;
    const uint32_t remaining = candidate_.exactSizeBytes - offset;
    const uint32_t want = remaining > kOtaBlockMaxDataBytes ? kOtaBlockMaxDataBytes : remaining;
    if (out == nullptr || out_capacity < want) return Result::BadRequest;
    if (staging_sink_->readChunk(offset, out, want) != meshcore::ota::runtime::IOtaStagingSink::Result::Ok) {
      return Result::IoError;
    }
    out_len = want;
    return Result::Ok;
  }

  void restore() {
    pending_reupload_ = false;
    seal_pending_ = false;
    commit_started_ = false;
    commit_sink_done_ = false;
    storage_unavailable_ = false;
    candidate_ = ::ota::storage::OtaCandidateStore::Snapshot();
    if (store_ == nullptr) return;
    const auto loaded = store_->load(candidate_);
    if (loaded == ::ota::storage::OtaCandidateStore::LoadResult::IoError) {
      // Never fall back to an older slot or "no candidate" behind unreadable state.
      candidate_ = ::ota::storage::OtaCandidateStore::Snapshot();
      storage_unavailable_ = true;
      return;
    }
    if (loaded != ::ota::storage::OtaCandidateStore::LoadResult::Found) return;
    seal_pending_ = candidate_.phase == ::ota::storage::OtaCandidateStore::Phase::Verifying;
  }

  __attribute__((noinline)) Status status() const {
    auto out = snapshotStatus(candidate_);
    out.storageUnavailable = storage_unavailable_;
    return out;
  }

  // Inspect the journal/bitmap without restoring the receiver, resuming its sink, or clearing a fault latch.
  Status inspectStatus() const {
    if (!store_ || storage_unavailable_) return status();
    ::ota::storage::OtaCandidateStore::Snapshot snapshot;
    const auto result = store_->load(snapshot);
    auto out = snapshotStatus(snapshot);
    out.storageUnavailable = result == ::ota::storage::OtaCandidateStore::LoadResult::IoError;
    if (snapshot.valid) {
      meshcore::ota::protocol::OtaDescriptor descriptor;
      if (meshcore::ota::protocol::decodeOtaDescriptorCanonical(snapshot.canonical, sizeof(snapshot.canonical),
            descriptor) != meshcore::ota::protocol::OtaDescriptorCodecResult::Ok ||
          !descriptor.exactSizeBytes || descriptor.formatId != 1 || descriptor.algorithmId != 1 ||
          !descriptor.keyId || !descriptor.appAddress ||
          descriptor.exactSizeBytes > ::ota::storage::OtaCandidateStore::kMaxBlocks * kOtaBlockMaxDataBytes ||
          descriptor.exactSizeBytes != snapshot.exactSizeBytes ||
          snapshot.totalBlocks != (descriptor.exactSizeBytes + kOtaBlockMaxDataBytes - 1u) / kOtaBlockMaxDataBytes ||
          snapshot.receivedBlocks > snapshot.totalBlocks) {
        out = Status();
        out.storageUnavailable = true;
      }
    }
    return out;
  }

  static Status snapshotStatus(const ::ota::storage::OtaCandidateStore::Snapshot& candidate) {
    Status out;
    out.valid = candidate.valid;
    out.localCache = candidate.localCache;
    out.phase = candidate.phase;
    out.receivedBlocks = candidate.receivedBlocks;
    out.totalBlocks = candidate.totalBlocks;
    out.imageBytes = candidate.exactSizeBytes;
    out.generation = candidate.sessionId;
    std::memcpy(out.ownerPublicKey, candidate.ownerPublicKey, sizeof(out.ownerPublicKey));
    std::memcpy(out.beginNonce, candidate.beginNonce, sizeof(out.beginNonce));
    if (candidate.valid) {
      meshcore::ota::runtime::OtaSessionId session;
      session.campaignId = candidate.campaignId;
      session.sessionId = candidate.sessionId;
      session.attemptId = candidate.attemptId;
      out.transactionNonce = meshcore::ota::runtime::otaInstallAttemptNonce(candidate.ownerPublicKey, session,
                                                                          candidate.canonical);
      out.counter = usb::getBE32(candidate.canonical + 45);
      computeOtaManifestHash(candidate.canonical, out.manifestHash);
      meshcore::ota::protocol::OtaDescriptor descriptor;
      if (meshcore::ota::protocol::decodeOtaDescriptorCanonical(candidate.canonical,
            sizeof(candidate.canonical), descriptor) == meshcore::ota::protocol::OtaDescriptorCodecResult::Ok) {
        std::memcpy(out.imageHash, descriptor.sha256, sizeof(out.imageHash));
      }
    }
    return out;
  }

  Result begin(const uint8_t owner_public_key[32],
               const uint8_t canonical[mesh::ota::kOtaCanonicalManifestBytes],
               const uint8_t signature[64], bool reupload, bool local_owner_trusted, bool local_cache = false) {
    if (store_ == nullptr || staging_sink_ == nullptr || trust_provider_ == nullptr ||
        owner_public_key == nullptr || canonical == nullptr || signature == nullptr) {
      return Result::Unavailable;
    }
    if (!reloadStorage()) return Result::Unavailable;

    meshcore::ota::protocol::OtaDescriptor descriptor;
    if (meshcore::ota::protocol::decodeOtaDescriptorCanonical(
            canonical, mesh::ota::kOtaCanonicalManifestBytes, descriptor) !=
        meshcore::ota::protocol::OtaDescriptorCodecResult::Ok) {
      return Result::BadRequest;
    }
    if (local_cache && (descriptor.formatId != 1 || descriptor.algorithmId != 1 ||
        descriptor.keyId == 0 || descriptor.appAddress == 0)) return Result::BadRequest;
    if (descriptor.exactSizeBytes == 0 ||
        descriptor.exactSizeBytes > ::ota::storage::OtaCandidateStore::kMaxBlocks * kOtaBlockMaxDataBytes) return Result::Denied;
    if (!local_cache && !trust_provider_->verifyDescriptorPolicyOnly(descriptor)) return Result::Denied;
    if (!verifyOwnerSignature(owner_public_key, canonical, mesh::ota::kOtaCanonicalManifestBytes, signature) ||
        !(local_owner_trusted || isCurrentAdmin(owner_public_key))) {
      return Result::Denied;
    }

    uint8_t manifest_hash[32] = {};
    computeOtaManifestHash(canonical, manifest_hash);
    const bool same_candidate = candidate_.valid &&
        candidate_.localCache == local_cache &&
        std::memcmp(candidate_.ownerPublicKey, owner_public_key, 32) == 0 &&
        std::memcmp(candidate_.canonical, canonical, sizeof(candidate_.canonical)) == 0;
    using Phase = ::ota::storage::OtaCandidateStore::Phase;
    const bool terminal = candidate_.valid && !candidate_.localCache &&
        (candidate_.phase == Phase::Committed || candidate_.phase == Phase::Ready || candidate_.phase == Phase::Failed) &&
        terminal_check_ && terminal_check_(terminal_ctx_, candidate_);
    // A legacy v1 attempt (zero nonce) can never COMMIT; a fresh signed BEGIN
    // for the same image restarts it as a nonce-bound attempt.
    const bool unbound_attempt = same_candidate && !usb::beginNonceBound(candidate_.beginNonce) &&
        (candidate_.phase == Phase::Receiving || candidate_.phase == Phase::Verifying ||
         candidate_.phase == Phase::Ready);
    if (!reupload && same_candidate && !unbound_attempt &&
        (candidate_.phase == Phase::Receiving || candidate_.phase == Phase::Verifying ||
         candidate_.phase == Phase::Ready || (candidate_.phase == Phase::Committed && !terminal))) {
      candidate_.receivedBlocks = store_->countReceived(candidate_.totalBlocks);
      return Result::Ok;
    }
    if (candidate_.valid && candidate_.phase != Phase::Idle && !terminal) {
      const bool same_content_owner = candidate_.localCache == local_cache &&
          !std::memcmp(candidate_.ownerPublicKey, owner_public_key, 32) &&
          candidateImageMatches(descriptor.sha256);
      if (candidate_.phase == Phase::Aborted) {
        if (!reupload) return same_candidate ? Result::Denied : Result::Busy;
      } else {
        if (!same_content_owner) return Result::Busy;
        if (!reupload && !unbound_attempt) return Result::Denied;
      }
    }
    if (candidate_.valid && candidate_.phase == Phase::Aborted && !candidate_.localCache && unadmitted_abort_) {
      const auto recovered = unadmitted_abort_(unadmitted_ctx_, candidate_, true);
      if (recovered != Result::Ok) return recovered;
      commit_started_ = false;
      commit_sink_done_ = false;
    }
    if (!terminal && (commit_started_ || (candidate_.valid && candidate_.phase == Phase::Committed)))
      return Result::TooLate;
    // Every new attempt gets fresh durable entropy before any side effect;
    // generation alone restarts at 1 after an empty store.
    uint8_t begin_nonce[usb::kBeginNonceBytes];
    if (!drawBeginNonce(manifest_hash, begin_nonce)) return Result::Unavailable;

    const auto begin_result = staging_sink_->beginSession(descriptor);
    if (begin_result == meshcore::ota::runtime::IOtaStagingSink::Result::Rejected) return Result::Busy;
    if (begin_result == meshcore::ota::runtime::IOtaStagingSink::Result::IoError) return Result::IoError;

    return publishBegin(descriptor, manifest_hash, canonical, owner_public_key, signature, local_cache, begin_nonce);
  }

private:
  __attribute__((noinline)) bool candidateImageMatches(const uint8_t hash[32]) const {
    return !std::memcmp(status().imageHash, hash, 32);
  }
  __attribute__((noinline)) bool drawBeginNonce(const uint8_t manifest_hash[32],
                                                uint8_t out[usb::kBeginNonceBytes]) const {
    static constexpr char kDomain[] = "MeshCore/OTA/begin-nonce/v1";
    uint8_t entropy[32], digest[32];
    if (!fillEntropy(entropy, sizeof(entropy))) return false;
    ::ota::trust::Sha256 hash;
    hash.reset();
    hash.update(reinterpret_cast<const uint8_t*>(kDomain), sizeof(kDomain) - 1);
    hash.update(entropy, sizeof(entropy));
    hash.update(manifest_hash, 32);
    hash.finish(digest);
    std::memset(entropy, 0, sizeof(entropy));
    std::memcpy(out, digest, usb::kBeginNonceBytes);
    // All-zero is reserved for unbound legacy records.
    return usb::beginNonceBound(out);
  }

  __attribute__((noinline)) Result publishBegin(const meshcore::ota::protocol::OtaDescriptor& descriptor,
      const uint8_t manifest_hash[32], const uint8_t canonical[59], const uint8_t owner_public_key[32],
      const uint8_t signature[64], bool local_cache, const uint8_t begin_nonce[usb::kBeginNonceBytes]) {
    ::ota::storage::OtaCandidateStore::Snapshot next;
    next.valid = true;
    next.localCache = local_cache;
    next.phase = ::ota::storage::OtaCandidateStore::Phase::Receiving;
    next.exactSizeBytes = descriptor.exactSizeBytes;
    next.totalBlocks = totalBlocksFor(descriptor.exactSizeBytes);
    next.campaignId = manifestTagToU32(manifest_hash);
    next.sessionId = candidate_.valid ? candidate_.sessionId + 1u : 1u;
    next.attemptId = 1u;
    std::memcpy(next.canonical, canonical, sizeof(next.canonical));
    std::memcpy(next.ownerPublicKey, owner_public_key, sizeof(next.ownerPublicKey));
    std::memcpy(next.signature, signature, sizeof(next.signature));
    std::memcpy(next.beginNonce, begin_nonce, sizeof(next.beginNonce));
    if (!store_->reset(next)) {
      staging_sink_->abort();
      // The failed reset may have tombstoned or erased slots: adopt durable
      // state exactly as a cold boot would, never the stale RAM candidate.
      restore();
      if (!storage_unavailable_) tryResumeSink();
      return Result::IoError;
    }
    candidate_ = next;
    pending_reupload_ = false;
    seal_pending_ = false;
    commit_started_ = false;
    commit_sink_done_ = false;
    staging_sink_->onVerifiedWireDescriptor(candidate_.canonical, sizeof(candidate_.canonical),
                                            candidate_.signature, sizeof(candidate_.signature));
    meshcore::ota::runtime::OtaSessionId session;
    session.campaignId = candidate_.campaignId;
    session.sessionId = candidate_.sessionId;
    session.attemptId = candidate_.attemptId;
    staging_sink_->onAuthorizedSession(session, candidate_.ownerPublicKey);
    return Result::Ok;
  }

public:
  Result putBlock(uint16_t index, const uint8_t* data, size_t data_len) {
    if (storage_unavailable_) return Result::Unavailable;
    return acceptBlock(index, data, data_len);
  }

  Result handleUsbCacheFrame(const uint8_t* frame, size_t len, const uint8_t local_owner[32]) {
    if (!frame || len < 2 || frame[0] != usb::kCommand) return Result::BadRequest;
    if (!reloadStorage()) return Result::Unavailable;
    switch (static_cast<usb::UsbOtaOp>(frame[1])) {
      case usb::UsbOtaOp::CacheBegin: {
        if (len != usb::kCacheBeginTotalBytes || (frame[2] & ~usb::kCacheBeginFlagReupload)) {
          return Result::BadRequest;
        }
        const auto* owner = frame + 3;
        const auto* canonical = owner + usb::kPubKeyBytes;
        const auto* signature = canonical + usb::kCanonicalManifestBytes;
        return begin(owner, canonical, signature, (frame[2] & usb::kCacheBeginFlagReupload) != 0,
                     local_owner && !std::memcmp(owner, local_owner, usb::kPubKeyBytes), true);
      }
      case usb::UsbOtaOp::CachePut:
        if (len < usb::kCachePutMinTotalBytes || len > usb::kCachePutMaxTotalBytes ||
            frame[4] == 0 || frame[4] > kOtaBlockMaxDataBytes || len != 5u + frame[4]) {
          return Result::BadRequest;
        }
        if (candidate_.valid && !candidate_.localCache) return Result::Denied;
        return putBlock(usb::getBE16(frame + 2), frame + 5, frame[4]);
      case usb::UsbOtaOp::CacheSeal:
        if (len != usb::kCacheSealTotalBytes) return Result::BadRequest;
        if (candidate_.valid && !candidate_.localCache) return Result::Denied;
        return requestSeal();
      default:
        return Result::Unsupported;
    }
  }

  __attribute__((noinline)) Result handleSignedBlockFrame(const uint8_t* frame, size_t frame_len) {
    if (storage_unavailable_) return Result::Unavailable;
    if (!candidate_.valid || candidate_.localCache ||
        (candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Receiving &&
         candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Verifying &&
         candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Ready)) {
      return Result::NotFound;
    }
    if (!isCurrentAdmin(candidate_.ownerPublicKey)) return Result::Denied;
    OtaSignedBlockFrame parsed;
    uint8_t manifest_hash[32] = {};
    computeOtaManifestHash(candidate_.canonical, manifest_hash);
    if (frame && frame_len >= 100 && frame_len <= kOtaOwnerSignedBlockMaxBytes &&
        frame[0] == kOtaOwnerSignedBlockKind) {
      if (std::memcmp(frame + 1, candidate_.ownerPublicKey, 32) != 0) return Result::Denied;
      parsed.kind = frame[0];
      parsed.index = getOtaBlockIndexBe(frame + 33);
      parsed.data = frame + 35;
      parsed.dataLen = frame_len - 99;
      parsed.signature = parsed.data + parsed.dataLen;
    } else {
      if (!parseOtaSignedBlockFrame(frame, frame_len, parsed) || parsed.kind != kOtaSignedBlockKind) return Result::BadRequest;
      if (std::memcmp(parsed.manifestTag, manifest_hash, kOtaManifestTagBytes) != 0) return Result::Mismatch;
    }
    uint8_t message[kOtaBlockSignedMessageMaxBytes] = {};
    const size_t message_len = buildOtaBlockSignedMessage(manifest_hash, parsed.kind, parsed.index,
                                                          parsed.data, parsed.dataLen, message);
    if (!verifyOwnerSignature(candidate_.ownerPublicKey, message, message_len, parsed.signature)) {
      return Result::Denied;
    }
    if (parsed.index >= candidate_.totalBlocks) return Result::BadRequest;
    const uint32_t remaining = candidate_.exactSizeBytes - static_cast<uint32_t>(parsed.index) * kOtaBlockMaxDataBytes;
    if (parsed.dataLen != (remaining > kOtaBlockMaxDataBytes ? kOtaBlockMaxDataBytes : remaining)) return Result::Mismatch;
    if (store_->isReceived(parsed.index)) return Result::Ok;
    const auto result = acceptBlock(parsed.index, parsed.data, parsed.dataLen);
    if (result == Result::Ok && candidate_.receivedBlocks == candidate_.totalBlocks) requestSeal();
    return result;
  }

  Result requestSeal() {
    if (storage_unavailable_) return Result::Unavailable;
    if (!candidate_.valid) return Result::NotFound;
    if (candidate_.phase == ::ota::storage::OtaCandidateStore::Phase::Ready) return Result::Ok;
    if (candidate_.phase == ::ota::storage::OtaCandidateStore::Phase::Verifying) return Result::Pending;
    if (candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Receiving) return Result::TooLate;
    candidate_.receivedBlocks = store_->countReceived(candidate_.totalBlocks);
    if (candidate_.receivedBlocks != candidate_.totalBlocks) return Result::Incomplete;
    auto next = candidate_;
    next.phase = ::ota::storage::OtaCandidateStore::Phase::Verifying;
    if (!store_->append(next)) return Result::IoError;
    candidate_ = next;
    seal_pending_ = true;
    return Result::Pending;
  }

  void loop() {
    if (storage_unavailable_) return;
    if (!seal_pending_ && candidate_.valid && !candidate_.localCache &&
        candidate_.phase == ::ota::storage::OtaCandidateStore::Phase::Receiving &&
        candidate_.receivedBlocks == candidate_.totalBlocks) requestSeal();
    if (!seal_pending_ || !candidate_.valid) return;
    seal_pending_ = false;
    meshcore::ota::protocol::OtaDescriptor descriptor;
    if (trust_provider_ == nullptr || meshcore::ota::protocol::decodeOtaDescriptorCanonical(candidate_.canonical, sizeof(candidate_.canonical), descriptor) !=
        meshcore::ota::protocol::OtaDescriptorCodecResult::Ok ||
        !verifyOwnerSignature(candidate_.ownerPublicKey, candidate_.canonical, sizeof(candidate_.canonical), candidate_.signature) ||
        !trust_provider_->verifyStagedImageHashPolicyOnly(descriptor)) {
      auto next = candidate_;
      next.phase = ::ota::storage::OtaCandidateStore::Phase::Failed;
      if (store_->append(next)) candidate_ = next;
      else seal_pending_ = true;
      return;
    }
    auto next = candidate_;
    next.phase = ::ota::storage::OtaCandidateStore::Phase::Ready;
    next.receivedBlocks = next.totalBlocks;
    if (store_->append(next)) candidate_ = next;
    else seal_pending_ = true;
  }

  __attribute__((noinline)) Result commit(uint32_t counter, const uint8_t signature[64]) {
    if (!reloadStorage()) return Result::Unavailable;
    if (!candidate_.valid) return Result::NotFound;
    if (candidate_.localCache) return Result::Denied;
    const bool already_committed = candidate_.phase == ::ota::storage::OtaCandidateStore::Phase::Committed;
    if (candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Ready && !already_committed) return Result::TooLate;
    if (!have_target_public_key_ || signature == nullptr) return Result::BadRequest;
    if (!isCurrentAdmin(candidate_.ownerPublicKey)) return Result::Denied;
    // Legacy/unbound records can never be committed; a fresh BEGIN replaces them.
    if (!usb::beginNonceBound(candidate_.beginNonce)) return Result::Denied;
    if (!commitSignatureValid(counter, signature)) return Result::Denied;
    if (counter != usb::getBE32(candidate_.canonical + 45)) return Result::Mismatch;
    if (already_committed) return Result::Ok;
    if (!commit_sink_done_) {
      staging_sink_->onAdmittedOwnerIdentity(candidate_.ownerPublicKey);
      const bool already_started = commit_started_;
      commit_started_ = true;
      const auto result = staging_sink_->commit();
      if (result == meshcore::ota::runtime::IOtaStagingSink::Result::IoError) return Result::IoError;
      if (result != meshcore::ota::runtime::IOtaStagingSink::Result::Ok) {
        commit_started_ = already_started;
        return Result::Denied;
      }
      commit_sink_done_ = true;
    }
    // A boot command may already be durable even if the following
    // candidate journal append fails. Permit signed retry, not replacement.
    return publishCommitted();
  }

private:
  __attribute__((noinline)) bool commitSignatureValid(uint32_t counter, const uint8_t signature[64]) const {
    uint8_t manifest_hash[32] = {};
    computeOtaManifestHash(candidate_.canonical, manifest_hash);
    uint8_t message[usb::kCommitSignedBytes] = {};
    const size_t message_len = usb::buildCommitSignedMessage(target_public_key_, manifest_hash, counter,
                                                             candidate_.sessionId, candidate_.beginNonce, message);
    return verifyOwnerSignature(candidate_.ownerPublicKey, message, message_len, signature);
  }

  __attribute__((noinline)) bool matchesPreparedReupload(const uint8_t owner[32], const uint8_t hash[32]) const {
    Status pending;
    return pendingReuploadStatus(hash, pending) && !std::memcmp(owner, pending_owner_, 32);
  }

  __attribute__((noinline)) Result publishCommitted() {
    auto next = candidate_;
    next.phase = ::ota::storage::OtaCandidateStore::Phase::Committed;
    if (!store_->append(next)) return Result::IoError;
    candidate_ = next;
    return Result::Ok;
  }

public:
  Result abort(const uint8_t signer_public_key[32], const uint8_t signature[64], const uint8_t image_hash[32],
                uint32_t generation, bool local_owner_trusted = false) {
    return abortAuthorized(signer_public_key, signature, image_hash, generation, local_owner_trusted, false);
  }

  // Only the pairwise-authenticated admin CLI dispatcher may supply this identity.
  // This is not an unsigned RF/USB operation and never grants local-owner/cache privileges.
  Result abortAuthenticatedAdmin(const uint8_t admin_public_key[32], uint32_t generation,
                                  uint32_t counter, const uint8_t image_hash[32]) {
    if (!isCurrentAdmin(admin_public_key)) return Result::Denied;
    if (!store_ || !staging_sink_ || !have_target_public_key_) return Result::Unavailable;
    if (!generation || !image_hash) return Result::BadRequest;
    return abortAuthorized(admin_public_key, nullptr, image_hash, generation, false, true, counter);
  }

private:
  static bool matchesAbortGuard(const Status& st, uint32_t generation, uint32_t counter,
                                const uint8_t image_hash[32]) {
    return st.valid && image_hash && st.counter == counter &&
        !std::memcmp(st.imageHash, image_hash, 32) &&
        (st.generation == generation ||
         (st.phase == ::ota::storage::OtaCandidateStore::Phase::Aborted &&
          generation != UINT32_MAX && st.generation == generation + 1u));
  }

  Result abortAuthorized(const uint8_t signer_public_key[32], const uint8_t signature[64],
                          const uint8_t image_hash[32], uint32_t generation,
                          bool local_owner_trusted, bool authenticated_admin, uint32_t expected_counter = 0) {
    static std::atomic_flag busy = ATOMIC_FLAG_INIT;
    OtaBoardProofScratchLease lease(busy);
    if (!lease) return Result::Busy;
    auto& scratch = abortScratch();
    if (authenticated_admin) {
      const auto durable = inspectStatus();
      if (durable.storageUnavailable) return Result::Unavailable;
      if (!matchesAbortGuard(durable, generation, expected_counter, image_hash)) return Result::Mismatch;
      if (durable.localCache) return Result::Denied;
      // Adopt only this guarded, durably acknowledged revocation after a marker verification error.
      const auto cached = status();
      if (durable.phase == ::ota::storage::OtaCandidateStore::Phase::Aborted &&
          cached.valid && durable.generation == cached.generation + 1u &&
          !std::memcmp(durable.manifestHash, cached.manifestHash, 32) &&
          !std::memcmp(durable.ownerPublicKey, cached.ownerPublicKey, 32)) {
        candidate_.phase = ::ota::storage::OtaCandidateStore::Phase::Aborted;
        candidate_.sessionId = durable.generation;
        candidate_.receivedBlocks = durable.receivedBlocks;
        seal_pending_ = false;
      }
      if (!matchesAbortGuard(status(), generation, expected_counter, image_hash)) return Result::Mismatch;
    } else if (!reloadStorage()) {
      return Result::Unavailable;
    }
    if (!candidate_.valid) return Result::NotFound;
    const bool aborted = candidate_.phase == ::ota::storage::OtaCandidateStore::Phase::Aborted;
    // Durable ABORT advances sessionId; its original signature may still finish cleanup after reset.
    if (generation != candidate_.sessionId && !(aborted && generation == candidate_.sessionId - 1u))
      return Result::Mismatch;
    const bool committed = commit_started_ || candidate_.phase == ::ota::storage::OtaCandidateStore::Phase::Committed;
    if (authenticated_admin) {
      using Phase = ::ota::storage::OtaCandidateStore::Phase;
      if (candidate_.localCache || !isCurrentAdmin(signer_public_key)) return Result::Denied;
      if ((!aborted && committed) ||
          (!aborted && candidate_.sessionId == UINT32_MAX) ||
          (candidate_.phase != Phase::Receiving && candidate_.phase != Phase::Verifying &&
           candidate_.phase != Phase::Ready && !aborted) ||
          (terminal_check_ && terminal_check_(terminal_ctx_, candidate_))) return Result::TooLate;
    }
    if (committed && !unadmitted_abort_) return Result::TooLate;
    if (signer_public_key == nullptr || (!authenticated_admin && signature == nullptr) ||
        image_hash == nullptr || !have_target_public_key_) {
      return Result::BadRequest;
    }
    auto& descriptor = scratch.descriptor;
    if (meshcore::ota::protocol::decodeOtaDescriptorCanonical(candidate_.canonical, sizeof(candidate_.canonical), descriptor) !=
        meshcore::ota::protocol::OtaDescriptorCodecResult::Ok) {
      return Result::Mismatch;
    }
    if (std::memcmp(descriptor.sha256, image_hash, 32) != 0) return Result::Mismatch;
    if (!isCurrentAdmin(signer_public_key) &&
        !(local_owner_trusted && candidate_.localCache &&
          !std::memcmp(signer_public_key, candidate_.ownerPublicKey, 32) &&
          !std::memcmp(signer_public_key, target_public_key_, 32))) return Result::Denied;
    if (!authenticated_admin) {
      auto& message = scratch.message;
      std::memset(message, 0, sizeof(message));
      const size_t message_len = usb::buildAbortSignedMessage(target_public_key_, image_hash, generation, message);
      if (!verifyOwnerSignature(signer_public_key, message, message_len, signature)) return Result::Denied;
    }
    if (aborted) {
      if (authenticated_admin) {
        const auto durable = inspectStatus();
        if (durable.storageUnavailable) return Result::Unavailable;
        if (!matchesAbortGuard(durable, generation, expected_counter, image_hash)) return Result::Mismatch;
      }
      const auto recovered = !candidate_.localCache && unadmitted_abort_ ?
          unadmitted_abort_(unadmitted_ctx_, candidate_, true) : Result::Ok;
      if (recovered == Result::Ok) { commit_started_ = false; commit_sink_done_ = false; }
      return recovered;
    }
    if (!candidate_.localCache && unadmitted_abort_) {
      auto& proof = scratch.snapshot;
      proof = candidate_;
      if (committed) proof.phase = ::ota::storage::OtaCandidateStore::Phase::Committed;
      const auto checked = unadmitted_abort_(unadmitted_ctx_, proof, false);
      if (checked != Result::Ok) return checked;
    }
    if (authenticated_admin) {
      const auto durable = inspectStatus();
      if (durable.storageUnavailable) return Result::Unavailable;
      if (!matchesAbortGuard(durable, generation, expected_counter, image_hash) ||
          !matchesAbortGuard(status(), generation, expected_counter, image_hash)) return Result::Mismatch;
      if (!isCurrentAdmin(signer_public_key)) return Result::Denied;
      using Phase = ::ota::storage::OtaCandidateStore::Phase;
      const auto revocable = [](Phase phase) {
        return phase == Phase::Receiving || phase == Phase::Verifying || phase == Phase::Ready;
      };
      if (commit_started_ || !revocable(durable.phase) || !revocable(candidate_.phase)) return Result::TooLate;
    }
    auto& next = scratch.snapshot;
    next = candidate_;
    next.phase = ::ota::storage::OtaCandidateStore::Phase::Aborted;
    ++next.sessionId;
    if (!store_->append(next)) return Result::IoError;
    candidate_ = next;
    seal_pending_ = false;
    staging_sink_->abort();
    if (!candidate_.localCache && unadmitted_abort_) {
      // Durable ABORT precedes cancellation so a reset can finish the same authorized cleanup.
      commit_started_ = true;
      const auto recovered = unadmitted_abort_(unadmitted_ctx_, candidate_, true);
      if (recovered != Result::Ok) return recovered;
      commit_started_ = false;
      commit_sink_done_ = false;
    }
    return Result::Ok;
  }

private:
  struct AbortScratch {
    meshcore::ota::protocol::OtaDescriptor descriptor;
    uint8_t message[usb::kAbortSignedBytes];
    ::ota::storage::OtaCandidateStore::Snapshot snapshot;
  };
  __attribute__((noinline)) static AbortScratch& abortScratch() {
    static AbortScratch scratch;
    return scratch;
  }

  void tryResumeSink() {
    if (!candidate_.valid || staging_sink_ == nullptr) return;
    if (candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Receiving &&
        candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Verifying &&
        candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Ready &&
        candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Committed &&
        candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Aborted) {
      return;
    }
    meshcore::ota::protocol::OtaDescriptor descriptor;
    if (meshcore::ota::protocol::decodeOtaDescriptorCanonical(candidate_.canonical, sizeof(candidate_.canonical), descriptor) !=
        meshcore::ota::protocol::OtaDescriptorCodecResult::Ok) {
      return;
    }
    if (staging_sink_->resumeSession(descriptor) == meshcore::ota::runtime::IOtaStagingSink::Result::Ok) {
      staging_sink_->onVerifiedWireDescriptor(candidate_.canonical, sizeof(candidate_.canonical),
                                             candidate_.signature, sizeof(candidate_.signature));
      meshcore::ota::runtime::OtaSessionId session;
      session.campaignId = candidate_.campaignId;
      session.sessionId = candidate_.sessionId;
      session.attemptId = candidate_.attemptId;
      staging_sink_->onAuthorizedSession(session, candidate_.ownerPublicKey);
    }
  }

  static uint16_t totalBlocksFor(uint32_t exact_size_bytes) {
    return static_cast<uint16_t>((exact_size_bytes + kOtaBlockMaxDataBytes - 1u) / kOtaBlockMaxDataBytes);
  }

  static uint32_t manifestTagToU32(const uint8_t manifest_hash[32]) {
    return (static_cast<uint32_t>(manifest_hash[0]) << 24) |
           (static_cast<uint32_t>(manifest_hash[1]) << 16) |
           (static_cast<uint32_t>(manifest_hash[2]) << 8) |
           static_cast<uint32_t>(manifest_hash[3]);
  }

  bool isCurrentAdmin(const uint8_t public_key[32]) const {
    return admin_check_ != nullptr && public_key != nullptr && admin_check_(admin_ctx_, public_key);
  }

  bool verifyOwnerSignature(const uint8_t public_key[32], const uint8_t* message, size_t message_len,
                          const uint8_t signature[64]) const {
    if (public_key == nullptr || signature == nullptr || (message == nullptr && message_len != 0)) return false;
    return owner_signature_verifier_ != nullptr &&
           owner_signature_verifier_->verify(signature, 64, message, message_len, public_key, 32);
  }

  Result acceptBlock(uint16_t index, const uint8_t* data, size_t data_len) {
    if (!candidate_.valid || candidate_.phase != ::ota::storage::OtaCandidateStore::Phase::Receiving ||
        data == nullptr || data_len == 0 || data_len > kOtaBlockMaxDataBytes || index >= candidate_.totalBlocks) {
      return Result::BadRequest;
    }
    const uint32_t offset = static_cast<uint32_t>(index) * kOtaBlockMaxDataBytes;
    const uint32_t remaining = candidate_.exactSizeBytes - offset;
    const uint32_t expected_len = remaining > kOtaBlockMaxDataBytes ? kOtaBlockMaxDataBytes : remaining;
    if (data_len != expected_len) return Result::Mismatch;
    bool received = false;
    if (!store_->readReceived(index, received)) return Result::IoError;
    if (received) return Result::Ok;
    const auto write_result = staging_sink_->writeChunk(offset, data, data_len);
    if (write_result == meshcore::ota::runtime::IOtaStagingSink::Result::IoError) return Result::IoError;
    if (write_result != meshcore::ota::runtime::IOtaStagingSink::Result::Ok) return Result::Denied;
    if (!store_->markReceived(index)) {
      // A failed verification read can follow a durable bit write.
      candidate_.receivedBlocks = store_->countReceived(candidate_.totalBlocks);
      return Result::IoError;
    }
    ++candidate_.receivedBlocks;
    return Result::Ok;
  }

  meshcore::ota::runtime::IOtaTrustProvider* trust_provider_ = nullptr;
  meshcore::ota::runtime::IOtaStagingSink* staging_sink_ = nullptr;
  ::ota::storage::OtaCandidateStore* store_ = nullptr;
  ::ota::storage::OtaCandidateStore::Snapshot candidate_{};
  void* admin_ctx_ = nullptr;
  AdminCheckFn admin_check_ = nullptr;
  void* terminal_ctx_ = nullptr;
  TerminalCheckFn terminal_check_ = nullptr;
  void* unadmitted_ctx_ = nullptr;
  UnadmittedAbortFn unadmitted_abort_ = nullptr;
  void* entropy_ctx_ = nullptr;
  EntropyFn entropy_ = nullptr;
  bool storage_unavailable_ = false;
  uint8_t target_public_key_[32] = {0};
  bool have_target_public_key_ = false;
  bool seal_pending_ = false;
  bool commit_started_ = false;
  bool commit_sink_done_ = false;
  const ::ota::trust::SignatureVerifier* owner_signature_verifier_ = nullptr;
  bool pending_reupload_ = false;
  uint8_t pending_owner_[32] = {}, pending_canonical_[59] = {}, pending_signature_[64] = {};
};

}  // namespace ota
}  // namespace mesh
