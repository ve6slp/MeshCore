#pragma once

#include <cstring>
#include <helpers/ota/OtaV4Platform.h>
#include <ota/platform/FlashRegion.h>
#include <ota/trust/Sha256.h>

namespace ota { namespace storage {

class OtaV4Staging {
public:
  using Result = mesh::ota::v4::Result;
  explicit OtaV4Staging(platform::FlashRegion& payload) : payload_(payload) {}

  Result begin(uint32_t rawSize) {
    if (!payload_.isValid() || payload_.eraseUnitBytes() != 4096 ||
        payload_.programUnitBytes() != 1 || !rawSize || rawSize > payload_.sizeBytes())
      return Result::Invalid;
    rawSize_ = rawSize;
    writeOffset_ = UINT32_MAX;
    return Result::Ok;
  }
  void invalidate() { rawSize_ = 0; writeOffset_ = UINT32_MAX; }
  uint32_t rawSize() const { return rawSize_; }

  Result write(uint32_t offset, const uint8_t* bytes, size_t size) {
    if (!bytes || !size || size > mesh::ota::v4::kSliceBytes || !rawSize_ ||
        offset > rawSize_ || size > rawSize_ - offset) return Result::Invalid;
    if (offset % mesh::ota::v4::kChunkBytes == 0) {
      const uint32_t remaining = rawSize_ - offset;
      const uint32_t chunk = remaining < mesh::ota::v4::kChunkBytes ?
          remaining : mesh::ota::v4::kChunkBytes;
      const uint32_t erase = ((chunk + 4095) / 4096) * 4096;
      // Only the uncheckpointed chunk is erased, including after reboot.
      if (!platform::isOk(payload_.eraseRange(offset, erase))) return fail();
      writeOffset_ = offset;
    }
    if (offset != writeOffset_) return Result::State;
    uint8_t verify[mesh::ota::v4::kSliceBytes];
    if (!platform::isOk(payload_.program(offset, bytes, size)) ||
        !platform::isOk(payload_.read(offset, verify, size)) ||
        std::memcmp(bytes, verify, size)) return fail();
    writeOffset_ += size;
    return Result::Ok;
  }

  Result read(uint32_t offset, uint8_t* bytes, size_t size) const {
    if (!bytes || !size || !rawSize_ || offset > rawSize_ || size > rawSize_ - offset)
      return Result::Invalid;
    return platform::isOk(payload_.read(offset, bytes, size)) ? Result::Ok : Result::Io;
  }

  // Do not keep the hash workspace on a caller's signature-verification stack.
  __attribute__((noinline)) Result verifyImage(uint32_t rawSize, const uint8_t expected[32]) const {
    if (!expected || !rawSize || rawSize > payload_.sizeBytes()) return Result::Invalid;
    uint8_t bytes[256], actual[32];
    trust::Sha256 hash;
    for (uint32_t offset = 0; offset < rawSize;) {
      const uint32_t count = rawSize - offset < sizeof(bytes) ? rawSize - offset : sizeof(bytes);
      if (!platform::isOk(payload_.read(offset, bytes, count))) return Result::Io;
      hash.update(bytes, count);
      offset += count;
    }
    hash.finish(actual);
    return std::memcmp(actual, expected, 32) ? Result::Integrity : Result::Ok;
  }

private:
  Result fail() { writeOffset_ = UINT32_MAX; return Result::Io; }
  platform::FlashRegion& payload_;
  uint32_t rawSize_ = 0;
  uint32_t writeOffset_ = UINT32_MAX;
};

}}
