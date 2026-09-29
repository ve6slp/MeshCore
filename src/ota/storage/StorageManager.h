#pragma once

// Orchestrates chunked writes into the candidate region and durable,
// verified copies between candidate/backup/target regions, all built on
// top of FlashRegion's bounds-checked primitives. Every multi-step
// operation here follows write -> readback verify ordering per chunk, so a
// caller can detect a torn write immediately rather than discovering it
// only after a later, unrelated failure.

#include <stdint.h>
#include <cstring>
#include "ota/platform/FlashRegion.h"
#include "ota/platform/FlashTypes.h"

namespace ota {
namespace storage {

class StorageManager {
public:
  static constexpr uint32_t kMaxChunkBytes = 512;

  // Erases every sector covering `region`. Must be called before writing
  // fresh chunk data into a region that may hold a previous image.
  static bool erasePartition(platform::FlashRegion& region) {
    if (!region.isValid()) {
      return false;
    }
    return platform::isOk(region.eraseRange(0, region.sizeBytes()));
  }

  // Writes one chunk into `region` at `chunk_index * chunk_size_bytes` and
  // immediately reads it back to confirm the bytes landed correctly.
  // Returns false (without silently accepting a partial/incorrect write) on
  // any programming or verification failure.
  static bool writeAndVerifyChunk(platform::FlashRegion& region,
                                   uint32_t chunk_index,
                                   uint32_t chunk_size_bytes,
                                   const uint8_t* data,
                                   uint32_t data_len) {
    if (!region.isValid() || data == nullptr || chunk_size_bytes == 0 || data_len > chunk_size_bytes ||
        chunk_size_bytes > kMaxChunkBytes) {
      return false;
    }
    // Overflow-safe offset computation for the chunk's position.
    if (chunk_index > (0xFFFFFFFFu / chunk_size_bytes)) {
      return false;  // chunk_index * chunk_size_bytes would overflow uint32_t
    }
    const uint32_t offset = chunk_index * chunk_size_bytes;

    if (!platform::isOk(region.program(offset, data, data_len))) {
      return false;
    }

    uint8_t readback[kMaxChunkBytes];
    if (!platform::isOk(region.read(offset, readback, data_len))) {
      return false;
    }
    return std::memcmp(readback, data, data_len) == 0;
  }

  static bool readChunk(const platform::FlashRegion& region,
                         uint32_t chunk_index,
                         uint32_t chunk_size_bytes,
                         uint8_t* out,
                         uint32_t out_len) {
    if (!region.isValid() || out == nullptr || chunk_size_bytes == 0 || out_len > chunk_size_bytes) {
      return false;
    }
    if (chunk_index > (0xFFFFFFFFu / chunk_size_bytes)) {
      return false;
    }
    const uint32_t offset = chunk_index * chunk_size_bytes;
    return platform::isOk(region.read(offset, out, out_len));
  }

  // Progress-resumable, verified copy from `source` to `destination` over
  // `total_bytes`, using a fixed-size scratch buffer. `start_offset` lets a
  // caller resume a copy that was interrupted (e.g. per a journal
  // checkpoint's progress field) instead of restarting from zero. Returns
  // false immediately, and does not advance `progress_out`, on the first
  // chunk that fails to program+readback-verify (this is what makes a
  // crash mid-copy safely detectable and resumable rather than silently
  // "complete").
  static bool copyRangeVerified(const platform::FlashRegion& source,
                                 platform::FlashRegion& destination,
                                 uint32_t total_bytes,
                                 uint32_t start_offset,
                                 uint32_t& progress_out) {
    if (!source.isValid() || !destination.isValid()) {
      return false;
    }
    if (start_offset > total_bytes || total_bytes > source.sizeBytes() || total_bytes > destination.sizeBytes()) {
      return false;
    }

    progress_out = start_offset;
    uint8_t buf[kMaxChunkBytes];
    uint8_t readback[kMaxChunkBytes];

    while (progress_out < total_bytes) {
      const uint32_t remaining = total_bytes - progress_out;
      const uint32_t step = remaining > kMaxChunkBytes ? kMaxChunkBytes : remaining;

      if (!platform::isOk(source.read(progress_out, buf, step))) {
        return false;
      }
      if (!platform::isOk(destination.program(progress_out, buf, step))) {
        return false;
      }
      if (!platform::isOk(destination.read(progress_out, readback, step))) {
        return false;
      }
      if (std::memcmp(readback, buf, step) != 0) {
        return false;
      }
      progress_out += step;
    }
    return true;
  }

  // Full-region verified equality check (used to confirm a backup or
  // installed image byte-for-byte matches its source before trusting it).
  static bool regionsEqual(const platform::FlashRegion& a, const platform::FlashRegion& b, uint32_t total_bytes) {
    if (!a.isValid() || !b.isValid()) {
      return false;
    }
    if (total_bytes > a.sizeBytes() || total_bytes > b.sizeBytes()) {
      return false;
    }
    uint8_t buf_a[kMaxChunkBytes];
    uint8_t buf_b[kMaxChunkBytes];
    uint32_t offset = 0;
    while (offset < total_bytes) {
      const uint32_t remaining = total_bytes - offset;
      const uint32_t step = remaining > kMaxChunkBytes ? kMaxChunkBytes : remaining;
      if (!platform::isOk(a.read(offset, buf_a, step))) {
        return false;
      }
      if (!platform::isOk(b.read(offset, buf_b, step))) {
        return false;
      }
      if (std::memcmp(buf_a, buf_b, step) != 0) {
        return false;
      }
      offset += step;
    }
    return true;
  }
};

}  // namespace storage
}  // namespace ota
