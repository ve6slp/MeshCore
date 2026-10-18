#pragma once

#include "OtaV4Platform.h"
#include <ota/protocol/OtaDescriptor.h>

namespace mesh { namespace ota { namespace v4 {

using Descriptor = meshcore::ota::protocol::OtaDescriptor;

struct Chunk {
  Codec codec = Codec::Raw;
  uint16_t storedSize = 0;
  const uint8_t* rawHash = nullptr;
};

// A bounded view; the caller retains immutable manifest bytes for its lifetime.
class Manifest {
public:
  Result parse(const uint8_t* bytes, size_t size);
  Result authorize(Platform& platform) const;
  Chunk chunk(uint16_t index) const;
  size_t rawSize(uint16_t index) const;
  const Descriptor& descriptor() const { return descriptor_; }
  const uint8_t* bytes() const { return bytes_; }
  size_t size() const { return size_; }
  uint16_t count() const { return count_; }
  const uint8_t* signer() const { return bytes_ ? bytes_ + 8 : nullptr; }
  const uint8_t* canonical() const { return bytes_ ? bytes_ + 40 : nullptr; }
  const uint8_t* bootSignature() const { return bytes_ ? bytes_ + 99 : nullptr; }
  const uint8_t* hash() const { return hash_; }

private:
  const uint8_t* bytes_ = nullptr;
  size_t size_ = 0;
  uint16_t count_ = 0;
  Descriptor descriptor_{};
  uint8_t hash_[32] = {};
};

}}}
