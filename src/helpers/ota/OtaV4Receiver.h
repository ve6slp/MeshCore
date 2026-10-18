#pragma once

#include "OtaV4Package.h"
#include "OtaLzma.h"
#include <ota/trust/Sha256.h>

namespace mesh { namespace ota { namespace v4 {

// One instance, retained for the device lifetime. Instance-owned workspaces
// must not be put on a small task stack. No heap allocation or host algorithm.
class Receiver {
public:
  explicit Receiver(Platform& platform) : platform_(platform) {}
  Result begin();
  Result onFrame(const uint8_t* bytes, size_t size);
  Result tick();
  const uint8_t* peek(size_t& size) const;
  void release();
  const Journal& journal() const { return journal_; }
  const uint8_t* challenge() const { return challenge_; }
  const Manifest& manifest() const { return manifest_; }

private:
  enum class Work : uint8_t { None, Decode, Thumb, HashChunk, WriteChunk, HashImage, RecoverChunk };
  Result result(Result value);
  Result fault(Result value);
  Result save(const Journal& next);
  Result rotateChallenge();
  Result assemble(const Frame& frame, uint8_t* buffer, size_t capacity,
                  uint64_t& mask, uint16_t& total);
  Result control(const Frame& frame);
  Result command(Kind kind, const uint8_t* bytes, size_t size);
  Result admit(const uint8_t* bytes);
  Result activate();
  Result abort();
  Result repair();
  Result status(uint16_t object, const uint8_t nonce[16]);
  Result progress(uint16_t object);
  Result reply(Kind kind, uint16_t object, const uint8_t* bytes, size_t size);
  void prepareReply();
  uint64_t missing() const;
  void resetChunk();
  Result startImageHash();
  Result finishChunk();
  Result recoverNext();

  Platform& platform_;
  Journal journal_{};
  Manifest manifest_;
  bool started_ = false, recovering_ = false;
  uint8_t identity_[32] = {}, challenge_[16] = {};
  uint8_t manifestBytes_[kMaxManifestBytes] = {};
  size_t manifestSize_ = 0;
  uint64_t manifestMask_ = 0;
  uint16_t manifestTotal_ = 0;
  uint8_t manifestTag_[8] = {};
  uint8_t controlBytes_[kMaxControlBytes] = {};
  uint64_t controlMask_ = 0;
  uint16_t controlTotal_ = 0, controlObject_ = 0;
  Kind controlKind_ = Kind::Query;
  uint8_t controlTag_[8] = {};
  uint8_t stored_[kChunkBytes] = {}, raw_[kChunkBytes] = {};
  uint64_t chunkMask_ = 0;
  uint16_t chunkTotal_ = 0, recoveryIndex_ = 0;
  Work work_ = Work::None;
  size_t cursor_ = 0;
  ::ota::trust::Sha256 hash_;
  OtaLzma decoder_;
  uint8_t replyBytes_[kStatusBytes] = {}, replyFrame_[kMaxFrameBytes] = {};
  size_t replySize_ = 0, replyFrameSize_ = 0;
  uint8_t replySlice_ = 0, replyTag_[8] = {};
  uint16_t replyObject_ = 0;
  uint32_t replyAttempt_ = 0;
  Kind replyKind_ = Kind::Status;
};

}}}
