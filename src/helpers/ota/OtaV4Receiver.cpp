#include "OtaV4Receiver.h"

namespace mesh { namespace ota { namespace v4 {
namespace {
bool equal(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t diff = 0;
  for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i];
  return diff == 0;
}
bool zero(const uint8_t* p, size_t n) {
  uint8_t bits = 0;
  for (size_t i = 0; i < n; ++i) bits |= p[i];
  return !bits;
}
bool live(Phase phase) {
  return phase == Phase::ActivationPending || phase == Phase::Trial;
}
}

Result Receiver::result(Result value) {
  journal_.lastResult = value;
  return value;
}

Result Receiver::fault(Result value) {
  work_ = Work::None;
  recovering_ = false;
  candidateCounter_ = 0;
  journal_.phase = Phase::MetadataFault;
  return result(value);
}

Result Receiver::rotateChallenge() {
  uint8_t next[16];
  const Result r = platform_.random(next, sizeof(next));
  if (r != Result::Ok) return fault(r);
  if (zero(next, sizeof(next)) || equal(next, challenge_, sizeof(next))) return fault(Result::Integrity);
  std::memcpy(challenge_, next, sizeof(next));
  return Result::Ok;
}

Result Receiver::save(const Journal& next) {
  const Result r = platform_.save(next, manifestSize_ ? manifestBytes_ : nullptr, manifestSize_);
  if (r != Result::Ok) return fault(r);
  journal_ = next;
  return Result::Ok;
}

Result Receiver::begin() {
  started_ = false;
  journal_ = Journal{};
  manifest_ = Manifest{};
  manifestSize_ = manifestMask_ = manifestTotal_ = 0;
  controlMask_ = controlTotal_ = 0;
  replySize_ = replyFrameSize_ = 0;
  recovering_ = false;
  candidateCounter_ = 0;
  resetChunk();
  Result r = platform_.identity(identity_);
  if (r != Result::Ok) return fault(r);
  r = rotateChallenge();
  if (r != Result::Ok) return r;
  started_ = true;
  r = platform_.recover(journal_, manifestBytes_, sizeof(manifestBytes_), manifestSize_);
  if (r == Result::State) {
    journal_ = Journal{};
    manifestSize_ = 0;
    return Result::Ok;
  }
  if (r != Result::Ok) return fault(r);
  if (static_cast<uint8_t>(journal_.phase) > static_cast<uint8_t>(Phase::MetadataFault) ||
      static_cast<uint8_t>(journal_.lastResult) > static_cast<uint8_t>(Result::Replay))
    return fault(Result::Integrity);
  if (journal_.phase == Phase::Idle) {
    if (manifestSize_ || journal_.nextChunk || !zero(journal_.packageHash, 32) ||
        !zero(journal_.transaction, 16)) return fault(Result::Integrity);
    return Result::Ok;
  }
  if (journal_.phase == Phase::MetadataFault) return fault(Result::Integrity);
  if (manifest_.parse(manifestBytes_, manifestSize_) != Result::Ok ||
      !equal(journal_.packageHash, manifest_.hash(), 32) || !journal_.generation ||
      zero(journal_.transaction, 16) || journal_.nextChunk > manifest_.count())
    return fault(Result::Integrity);
  // Recovery authenticates the recorded bytes, not their former authority.
  // Current authority and floor are checked again before any new installation.
  if (!platform_.verify(manifest_.signer(), nullptr, 0, manifest_.canonical(), 59,
                        manifest_.bootSignature()) ||
      !platform_.verify(manifest_.signer(), kManifestDomain, sizeof(kManifestDomain),
                        manifestBytes_, manifestSize_ - 64, manifestBytes_ + manifestSize_ - 64))
    return fault(Result::Integrity);
  candidateCounter_ = manifest_.descriptor().securityCounter;
  if (journal_.phase == Phase::Receiving || journal_.phase == Phase::Verifying ||
      journal_.phase == Phase::Ready) {
    if (journal_.phase != Phase::Receiving && journal_.nextChunk != manifest_.count())
      return fault(Result::Integrity);
    if (journal_.nextChunk) {
      journal_.phase = Phase::Verifying;
      recovering_ = true;
      recoveryIndex_ = 0;
      cursor_ = 0;
      hash_.reset();
      work_ = Work::RecoverChunk;
    } else {
      r = platform_.beginStaging(manifest_.descriptor().exactSizeBytes);
      if (r != Result::Ok) return fault(r);
    }
  }
  return Result::Ok;
}

Result Receiver::assemble(const Frame& frame, uint8_t* buffer, size_t capacity,
                          uint64_t& mask, uint16_t& total) {
  if (frame.total > capacity) return Result::Invalid;
  if (!mask) total = frame.total;
  if (total != frame.total) return Result::Invalid;
  const uint64_t bit = UINT64_C(1) << frame.slice;
  const size_t offset = static_cast<size_t>(frame.slice) * kSliceBytes;
  if (mask & bit) return equal(buffer + offset, frame.data, frame.size) ?
      Result::Ok : Result::Integrity;
  std::memcpy(buffer + offset, frame.data, frame.size);
  mask |= bit;
  return Result::Ok;
}

Result Receiver::onFrame(const uint8_t* bytes, size_t size) {
  if (!started_) return Result::State;
  Frame f;
  if (!decodeFrame(bytes, size, f)) return result(Result::Invalid);
  if (f.kind == Kind::Status || f.kind == Kind::Progress) return result(Result::Unsupported);
  if (f.kind == Kind::Manifest) {
    if (f.object || journal_.phase == Phase::MetadataFault || live(journal_.phase) ||
        journal_.phase == Phase::Receiving || journal_.phase == Phase::Verifying ||
        journal_.phase == Phase::Ready) return result(Result::State);
    if (manifestMask_ && !equal(f.tag, manifestTag_, 8)) {
      if (f.slice) return result(Result::Busy);
      manifestMask_ = manifestTotal_ = 0;
      manifestSize_ = 0;
      manifest_ = Manifest{};
    }
    if (!manifestMask_) {
      std::memcpy(manifestTag_, f.tag, 8);
      manifestSize_ = 0;
      manifest_ = Manifest{};
    }
    Result r = assemble(f, manifestBytes_, sizeof(manifestBytes_), manifestMask_, manifestTotal_);
    if (r != Result::Ok) return result(r);
    if (manifestMask_ != sliceMask(f.total)) return result(Result::Ok);
    r = manifest_.parse(manifestBytes_, f.total);
    if (r == Result::Ok && !equal(f.tag, manifest_.hash(), 8)) r = Result::Integrity;
    if (r == Result::Ok) r = manifest_.authorize(platform_);
    if (r != Result::Ok) {
      manifestMask_ = manifestTotal_ = 0; manifest_ = Manifest{};
      return result(r);
    }
    manifestSize_ = f.total;
    return result(Result::Ok);
  }
  if (f.kind == Kind::Data) {
    if (journal_.phase != Phase::Receiving || recovering_ || !manifestSize_)
      return result(Result::State);
    if (!equal(f.tag, journal_.packageHash, 8)) return result(Result::Denied);
    if (f.object < journal_.nextChunk) return result(Result::Ok);
    if (f.object != journal_.nextChunk || f.object >= manifest_.count())
      return result(Result::State);
    if (work_ != Work::None) return result(Result::Busy);
    const Chunk c = manifest_.chunk(f.object);
    if (f.total != c.storedSize) return result(Result::Invalid);
    const Result r = assemble(f, stored_, sizeof(stored_), chunkMask_, chunkTotal_);
    if (r != Result::Ok) return result(r);
    if (chunkMask_ == sliceMask(f.total)) {
      cursor_ = 0;
      if (c.codec == Codec::Raw) {
        work_ = Work::HashChunk;
        hash_.reset();
      } else {
        if (decoder_.begin(stored_, c.storedSize, raw_, manifest_.rawSize(f.object)) !=
            OtaLzma::Result::Pending) return result(Result::Integrity);
        work_ = Work::Decode;
      }
    }
    return result(Result::Ok);
  }
  return result(control(f));
}

Result Receiver::control(const Frame& f) {
  size_t expected = 0;
  switch (f.kind) {
    case Kind::Query: expected = kQueryBytes; break;
    case Kind::ProgressQuery: expected = kProgressQueryBytes; break;
    case Kind::Admit: case Kind::Activate: case Kind::Abort: case Kind::Repair:
      expected = kCommandBytes; break;
    case Kind::Lease: expected = kLeaseCommandBytes; break;
    default: return Result::Unsupported;
  }
  if (f.total != expected ||
      (f.kind != Kind::Query && f.kind != Kind::ProgressQuery && f.object))
    return Result::Invalid;
  if (f.kind == Kind::Query) {
    if (!zero(f.tag, 8)) return Result::Invalid;
  } else if (f.kind == Kind::Repair) {
    if (!zero(f.tag, 8)) return Result::Invalid;
  } else {
    const uint8_t* tag = f.kind == Kind::Admit && manifestSize_ ?
        manifest_.hash() : journal_.packageHash;
    if (!equal(f.tag, tag, 8)) return Result::Denied;
  }
  if (controlMask_ && (f.kind != controlKind_ || f.object != controlObject_ ||
                       !equal(f.tag, controlTag_, 8))) {
    if (f.slice) return Result::Busy;
    controlMask_ = controlTotal_ = 0;
  }
  if (!controlMask_) {
    controlKind_ = f.kind; controlObject_ = f.object;
    std::memcpy(controlTag_, f.tag, 8);
  }
  const Result r = assemble(f, controlBytes_, sizeof(controlBytes_), controlMask_, controlTotal_);
  if (r != Result::Ok) return r;
  if (controlMask_ != sliceMask(f.total)) return Result::Ok;
  controlMask_ = controlTotal_ = 0;
  if (f.kind == Kind::Query) {
    if (!equal(controlBytes_, identity_, 32)) return Result::Denied;
    return status(f.object, controlBytes_ + 32);
  }
  if (f.kind == Kind::ProgressQuery) {
    if (!equal(controlBytes_, identity_, 32)) return Result::Denied;
    return progress(f.object);
  }
  return command(f.kind, controlBytes_, expected);
}

Result Receiver::command(Kind kind, const uint8_t* b, size_t size) {
  uint8_t identity[32];
  const Result identityResult = platform_.identity(identity);
  if (identityResult != Result::Ok) return identityResult;
  if (!equal(identity, identity_, 32)) return Result::Denied;
  if (!equal(b + 32, identity_, 32) || !platform_.isCurrentAdmin(b)) return Result::Denied;
  const char* domain = nullptr;
  size_t domainSize = 0;
  switch (kind) {
    case Kind::Admit: domain = kAdmitDomain; domainSize = sizeof(kAdmitDomain); break;
    case Kind::Activate: domain = kActivateDomain; domainSize = sizeof(kActivateDomain); break;
    case Kind::Abort: domain = kAbortDomain; domainSize = sizeof(kAbortDomain); break;
    case Kind::Repair: domain = kRepairDomain; domainSize = sizeof(kRepairDomain); break;
    case Kind::Lease: domain = kLeaseDomain; domainSize = sizeof(kLeaseDomain); break;
    default: return Result::Unsupported;
  }
  if (!platform_.verify(b, domain, domainSize, b, size - 64, b + size - 64))
    return Result::Denied;
  if (read32(b + 112) != journal_.generation) return Result::Replay;
  const bool challenge = kind == Kind::Admit || kind == Kind::Repair || kind == Kind::Lease;
  if (!equal(b + 96, challenge ? challenge_ : journal_.transaction, 16)) return Result::Replay;
  const uint8_t* package = kind == Kind::Admit && manifestSize_ ?
      manifest_.hash() : journal_.packageHash;
  if (kind == Kind::Repair) {
    if (!zero(b + 64, 32)) return Result::Invalid;
  } else if (!equal(b + 64, package, 32)) return Result::Denied;
  switch (kind) {
    case Kind::Admit: return admit(b);
    case Kind::Activate: return activate();
    case Kind::Abort: return abort();
    case Kind::Repair: return repair();
    case Kind::Lease: {
      const uint32_t duration = read32(b + 126);
      if (duration > 60000) return Result::Invalid;
      // Reserve fresh entropy before applying the override.
      uint8_t next[16];
      Result r = platform_.random(next, sizeof(next));
      if (r != Result::Ok) return r;
      if (zero(next, 16) || equal(next, challenge_, 16)) return Result::Integrity;
      r = platform_.lease(read32(b + 116), read32(b + 120), b[124], b[125], duration);
      if (r != Result::Ok) return r;
      std::memcpy(challenge_, next, 16);
      return Result::Ok;
    }
    default: return Result::Unsupported;
  }
}

Result Receiver::admit(const uint8_t*) {
  if (!manifestSize_ || (journal_.phase != Phase::Idle && journal_.phase != Phase::Aborted &&
                         journal_.phase != Phase::Failed && journal_.phase != Phase::Confirmed))
    return Result::State;
  if (journal_.generation == UINT32_MAX) return Result::Replay;
  Result r = manifest_.authorize(platform_);
  if (r != Result::Ok) return r;
  Journal next{};
  next.phase = Phase::Receiving;
  next.generation = journal_.generation + 1;
  std::memcpy(next.packageHash, manifest_.hash(), 32);
  r = platform_.random(next.transaction, 16);
  if (r != Result::Ok) return r;
  if (zero(next.transaction, 16) || equal(next.transaction, challenge_, 16))
    return Result::Integrity;
  r = save(next);
  if (r != Result::Ok) return r;
  candidateCounter_ = manifest_.descriptor().securityCounter;
  resetChunk();
  r = platform_.beginStaging(manifest_.descriptor().exactSizeBytes);
  if (r != Result::Ok) return fault(r);
  return rotateChallenge();
}

Result Receiver::activate() {
  if (journal_.phase != Phase::Ready || work_ != Work::None) return Result::State;
  Result r = manifest_.authorize(platform_);
  if (r != Result::Ok) return r;
  r = platform_.validateInstall(manifest_.canonical(), manifest_.bootSignature(), manifest_.signer());
  if (r != Result::Ok) return r;
  Journal next = journal_;
  next.phase = Phase::ActivationPending; next.lastResult = Result::Ok;
  r = save(next);
  if (r != Result::Ok) return r;
  r = platform_.activate(manifest_.canonical(), manifest_.bootSignature(), manifest_.signer(),
                         journal_.transaction, journal_.generation);
  // The durable command may exist even if publication returned an IO failure.
  // Keep ActivationPending and reconcile, never re-admit or abort uncertainty.
  return r;
}

Result Receiver::abort() {
  if (journal_.phase != Phase::Receiving && journal_.phase != Phase::Verifying &&
      journal_.phase != Phase::Ready)
    return Result::State;
  if (journal_.generation == UINT32_MAX) return Result::Replay;
  Journal next = journal_;
  next.phase = Phase::Aborted; next.lastResult = Result::Ok; ++next.generation;
  Result r = save(next);
  if (r != Result::Ok) return r;
  resetChunk(); recovering_ = false;
  r = rotateChallenge();
  if (r != Result::Ok) return r;
  return platform_.clearStaging();
}

Result Receiver::repair() {
  if (live(journal_.phase)) return Result::State;
  if (journal_.generation == UINT32_MAX) return Result::Replay;
  Journal next;
  next.generation = journal_.generation + 1;
  const Result r = platform_.repair(next);
  if (r != Result::Ok) return r;
  journal_ = next; manifest_ = Manifest{};
  candidateCounter_ = 0;
  manifestSize_ = manifestMask_ = manifestTotal_ = 0;
  resetChunk(); recovering_ = false;
  return rotateChallenge();
}

uint64_t Receiver::missing() const {
  if (!manifestSize_ || journal_.nextChunk >= manifest_.count() ||
      journal_.phase != Phase::Receiving || recovering_) return 0;
  return sliceMask(manifest_.chunk(journal_.nextChunk).storedSize) & ~chunkMask_;
}

Result Receiver::status(uint16_t object, const uint8_t nonce[16]) {
  if (replySize_) return Result::Busy;
  uint8_t identity[32];
  Result r = platform_.identity(identity);
  if (r != Result::Ok) return r;
  if (!equal(identity, identity_, 32)) return Result::Denied;
  RunningEvidence e;
  r = platform_.evidence(e);
  if (r != Result::Ok) return r;
  uint8_t* b = replyBytes_;
  std::memset(b, 0, kStatusBytes);
  std::memcpy(b, identity_, 32); std::memcpy(b + 32, nonce, 16);
  std::memcpy(b + 48, challenge_, 16); std::memcpy(b + 64, journal_.packageHash, 32);
  std::memcpy(b + 96, journal_.transaction, 16);
  write32(b + 112, journal_.generation);
  write32(b + 116, candidateCounter_);
  write32(b + 120, e.flags & FloorKnown ? e.floor : 0);
  b[124] = static_cast<uint8_t>(journal_.phase);
  b[125] = static_cast<uint8_t>(journal_.lastResult);
  write16(b + 126, journal_.nextChunk); write64(b + 128, missing());
  if (e.flags & RunningHashKnown) std::memcpy(b + 136, e.hash, 32);
  b[168] = e.flags & (FloorKnown | RunningHashKnown | RunningConfirmed);
  r = platform_.sign(kStatusDomain, sizeof(kStatusDomain), b, kSignedStatusBytes,
                     b + kSignedStatusBytes);
  if (r != Result::Ok) return r;
  return reply(Kind::Status, object, b, kStatusBytes);
}

Result Receiver::progress(uint16_t object) {
  if (replySize_) return Result::Busy;
  uint8_t* b = replyBytes_;
  std::memcpy(b, identity_, 32); write32(b + 32, journal_.generation);
  write16(b + 36, journal_.nextChunk); write64(b + 38, missing());
  b[46] = static_cast<uint8_t>(journal_.phase);
  b[47] = static_cast<uint8_t>(journal_.lastResult);
  return reply(Kind::Progress, object, b, kProgressBytes);
}

Result Receiver::reply(Kind kind, uint16_t object, const uint8_t* bytes, size_t size) {
  if (replySize_) return Result::Busy;
  if (bytes != replyBytes_) std::memcpy(replyBytes_, bytes, size);
  replyKind_ = kind; replyObject_ = object; replySize_ = size; replySlice_ = 0;
  std::memcpy(replyTag_, journal_.packageHash, 8);
  prepareReply();
  return replyFrameSize_ ? Result::Ok : Result::State;
}

void Receiver::prepareReply() {
  if (++replyAttempt_ == 0) ++replyAttempt_;
  const size_t n = sliceSize(replySize_, replySlice_);
  replyFrameSize_ = encodeFrame(replyKind_, replyAttempt_, replyTag_, replyObject_,
      static_cast<uint16_t>(replySize_), replySlice_,
      replyBytes_ + static_cast<size_t>(replySlice_) * kSliceBytes, n,
      replyFrame_, sizeof(replyFrame_));
}

const uint8_t* Receiver::peek(size_t& size) const {
  size = replyFrameSize_;
  return size ? replyFrame_ : nullptr;
}

void Receiver::release() {
  if (!replyFrameSize_) return;
  if ((static_cast<size_t>(++replySlice_) * kSliceBytes) >= replySize_) {
    replySize_ = replyFrameSize_ = 0;
  } else prepareReply();
}

void Receiver::resetChunk() {
  work_ = Work::None; cursor_ = 0; chunkMask_ = 0; chunkTotal_ = 0;
}

Result Receiver::startImageHash() {
  Journal next = journal_;
  next.phase = Phase::Verifying; next.lastResult = Result::Ok;
  const Result r = save(next);
  if (r != Result::Ok) return r;
  cursor_ = 0; hash_.reset(); work_ = Work::HashImage;
  return Result::Ok;
}

Result Receiver::finishChunk() {
  Journal next = journal_;
  ++next.nextChunk; next.lastResult = Result::Ok;
  const Result r = save(next);
  if (r != Result::Ok) return r;
  resetChunk();
  if (journal_.nextChunk == manifest_.count()) return startImageHash();
  return Result::Ok;
}

Result Receiver::recoverNext() {
  uint8_t digest[32]; hash_.finish(digest);
  if (!equal(digest, manifest_.chunk(recoveryIndex_).rawHash, 32)) return fault(Result::Integrity);
  if (++recoveryIndex_ < journal_.nextChunk) {
    cursor_ = 0; hash_.reset();
    return Result::Ok;
  }
  recovering_ = false;
  resetChunk();
  if (journal_.nextChunk == manifest_.count()) return startImageHash();
  Journal next = journal_; next.phase = Phase::Receiving;
  return save(next);
}

Result Receiver::tick() {
  if (!started_) return Result::State;
  if (journal_.phase == Phase::MetadataFault) return journal_.lastResult;
  if (live(journal_.phase)) {
    Phase phase = journal_.phase;
    const Result r = platform_.lifecycle(phase);
    if (r == Result::State) return Result::Ok;
    if (r != Result::Ok) return result(r);
    if (phase != Phase::Trial && phase != Phase::Confirmed && phase != Phase::Failed)
      return result(Result::Invalid);
    if (phase == Phase::Confirmed) {
      RunningEvidence e;
      const Result evidence = platform_.evidence(e);
      if (evidence != Result::Ok) return result(evidence);
      if ((e.flags & 7) != 7 || e.floor < manifest_.descriptor().securityCounter ||
          !equal(e.hash, manifest_.descriptor().sha256, 32)) return result(Result::Integrity);
    }
    if (phase == journal_.phase) return Result::Ok;
    Journal next = journal_; next.phase = phase; next.lastResult = Result::Ok;
    return save(next);
  }
  if (work_ == Work::None) return Result::Ok;
  const uint16_t index = recovering_ ? recoveryIndex_ : journal_.nextChunk;
  if (work_ == Work::Decode) {
    const auto r = decoder_.step();
    if (r == OtaLzma::Result::Pending) return Result::Ok;
    if (r != OtaLzma::Result::Ok) {
      resetChunk(); return result(Result::Integrity);
    }
    cursor_ = 0;
    work_ = manifest_.chunk(index).codec == Codec::LzmaThumb ? Work::Thumb : Work::HashChunk;
    hash_.reset();
    return Result::Ok;
  }
  if (work_ == Work::Thumb) {
    const size_t rawSize = manifest_.rawSize(index);
    const size_t n = rawSize - cursor_ > kSliceBytes ? kSliceBytes : rawSize - cursor_;
    uint8_t* start = raw_ + cursor_;
    const size_t done = lzma_sdk::Z7_BRANCH_CONV_DEC(ARMT)(
        start, n, static_cast<uint32_t>(cursor_)) - start;
    cursor_ += done;
    if (rawSize - cursor_ < 4) {
      cursor_ = 0; hash_.reset(); work_ = Work::HashChunk;
    } else if (!done) {
      resetChunk(); return result(Result::Integrity);
    }
    return Result::Ok;
  }
  if (work_ == Work::HashChunk) {
    const size_t rawSize = manifest_.rawSize(index);
    const size_t n = rawSize - cursor_ > kSliceBytes ? kSliceBytes : rawSize - cursor_;
    if (manifest_.chunk(index).codec == Codec::Raw)
      std::memcpy(raw_ + cursor_, stored_ + cursor_, n);
    hash_.update(raw_ + cursor_, n); cursor_ += n;
    if (cursor_ == rawSize) {
      uint8_t digest[32]; hash_.finish(digest);
      if (!equal(digest, manifest_.chunk(index).rawHash, 32)) {
        resetChunk(); return result(Result::Integrity);
      }
      cursor_ = 0; work_ = Work::WriteChunk;
    }
    return Result::Ok;
  }
  if (work_ == Work::WriteChunk) {
    const size_t rawSize = manifest_.rawSize(index);
    const size_t n = rawSize - cursor_ > kSliceBytes ? kSliceBytes : rawSize - cursor_;
    const Result r = platform_.writeStaging(static_cast<uint32_t>(index * kChunkBytes + cursor_),
                                           raw_ + cursor_, n);
    if (r != Result::Ok) return fault(r);
    cursor_ += n;
    return cursor_ == rawSize ? finishChunk() : Result::Ok;
  }
  const size_t total = work_ == Work::RecoverChunk ? manifest_.rawSize(index) :
      manifest_.descriptor().exactSizeBytes;
  const size_t n = total - cursor_ > kSliceBytes ? kSliceBytes : total - cursor_;
  const uint32_t offset = static_cast<uint32_t>(cursor_ +
      (work_ == Work::RecoverChunk ? index * kChunkBytes : 0));
  const Result r = platform_.readStaging(offset, raw_, n);
  if (r != Result::Ok) return fault(r);
  hash_.update(raw_, n); cursor_ += n;
  if (cursor_ != total) return Result::Ok;
  if (work_ == Work::RecoverChunk) return recoverNext();
  uint8_t digest[32]; hash_.finish(digest);
  work_ = Work::None;
  if (!equal(digest, manifest_.descriptor().sha256, 32)) {
    Journal next = journal_; next.phase = Phase::Failed; next.lastResult = Result::Integrity;
    const Result saved = save(next);
    return saved == Result::Ok ? Result::Integrity : saved;
  }
  const Result auth = manifest_.authorize(platform_);
  if (auth != Result::Ok) return result(auth);
  Journal next = journal_; next.phase = Phase::Ready; next.lastResult = Result::Ok;
  return save(next);
}

}}}
