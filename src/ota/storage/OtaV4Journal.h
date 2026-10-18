#pragma once

#include <cstring>
#include <helpers/ota/OtaV4Platform.h>
#include <ota/platform/FlashRegion.h>
#include <ota/storage/Crc32.h>
#include <ota/trust/Sha256.h>

namespace ota { namespace storage {

class OtaV4Journal {
public:
  using Journal = mesh::ota::v4::Journal;
  using Result = mesh::ota::v4::Result;
  using Phase = mesh::ota::v4::Phase;
  static constexpr uint32_t kHeaderBytes = 128;
  static constexpr uint32_t kMagic = 0x4D434A34;
  static constexpr uint32_t kMarker = 0x4A524E34;

  explicit OtaV4Journal(platform::FlashRegion& region) : region_(region) {}

  size_t manifestCapacity() const { return geometry() ? bankBytes() - kHeaderBytes : 0; }
  bool faulted() const { return fault_; }

  Result recover(Journal& journal, uint8_t* manifest, size_t capacity, size_t& size) {
    journal = Journal();
    size = 0;
    fault_ = false;
    loaded_ = true;
    sequence_ = 0;
    slot_ = 0;
    bool found = false, damaged = false;
    if (!geometry()) return fail(Result::Unsupported);
    uint8_t selected[kHeaderBytes] = {};
    for (uint32_t slot = 0; slot < 2; ++slot) {
      uint8_t header[kHeaderBytes];
      if (!read(slot * bankBytes(), header, sizeof(header))) return fail(Result::Io);
      bool blank = true;
      if (!blankRange(slot * bankBytes(), bankBytes(), blank)) return fail(Result::Io);
      if (blank) continue;
      const uint16_t length = mesh::ota::v4::read16(header + 12);
      if (!validHeader(header) || length > manifestCapacity()) {
        damaged = true;
        continue;
      }
      uint8_t digest[32];
      uint32_t crc = Crc32::compute(header, 104);
      if (!hashAndCrc(slot * bankBytes() + kHeaderBytes, length, digest, crc))
        return fail(Result::Io);
      bool tail = false;
      if (!blankRange(slot * bankBytes() + kHeaderBytes + length,
                       bankBytes() - kHeaderBytes - length, tail)) return fail(Result::Io);
      if (!tail || std::memcmp(digest, header + 72, 32) ||
          (crc ^ UINT32_MAX) != mesh::ota::v4::read32(header + 104)) {
        damaged = true;
        continue;
      }
      const uint32_t sequence = mesh::ota::v4::read32(header + 8);
      if (found && sequence == sequence_) {
        damaged = true;
      } else if (!found || sequence > sequence_) {
        found = true;
        sequence_ = sequence;
        slot_ = slot;
        std::memcpy(selected, header, sizeof(selected));
      }
    }
    // Invalid bytes might be newer revocation, not an ignorable old record.
    if (damaged) {
      if (found) decode(selected, journal);
      journal.phase = Phase::MetadataFault;
      return fail(Result::Integrity);
    }
    if (!found) return Result::State;
    decode(selected, journal);
    size = mesh::ota::v4::read16(selected + 12);
    if (size > capacity || (size && !manifest)) return fail(Result::Invalid);
    if (size && !read(slot_ * bankBytes() + kHeaderBytes, manifest, size)) {
      size = 0;
      return fail(Result::Io);
    }
    return Result::Ok;
  }

  Result save(const Journal& journal, const uint8_t* manifest, size_t size) {
    if (!loaded_ || fault_) return Result::State;
    if (!geometry() || size > manifestCapacity() || size > mesh::ota::v4::kMaxManifestBytes ||
        (size && !manifest) || sequence_ == UINT32_MAX || !validJournal(journal, size))
      return Result::Invalid;
    uint8_t header[kHeaderBytes] = {};
    mesh::ota::v4::write32(header, kMagic);
    mesh::ota::v4::write16(header + 4, 4);
    mesh::ota::v4::write16(header + 6, kHeaderBytes);
    mesh::ota::v4::write32(header + 8, sequence_ + 1);
    mesh::ota::v4::write16(header + 12, static_cast<uint16_t>(size));
    header[16] = static_cast<uint8_t>(journal.phase);
    header[17] = static_cast<uint8_t>(journal.lastResult);
    mesh::ota::v4::write16(header + 18, journal.nextChunk);
    mesh::ota::v4::write32(header + 20, journal.generation);
    std::memcpy(header + 24, journal.packageHash, 32);
    std::memcpy(header + 56, journal.transaction, 16);
    trust::Sha256 hash;
    if (size) hash.update(manifest, size);
    hash.finish(header + 72);
    if (size && std::memcmp(header + 72, journal.packageHash, 32)) return Result::Integrity;
    uint32_t crc = Crc32::compute(header, 104);
    if (size) crc = Crc32::compute(manifest, size, crc);
    mesh::ota::v4::write32(header + 104, crc ^ UINT32_MAX);
    mesh::ota::v4::write32(header + 108, kMarker);
    const uint32_t target = sequence_ ? 1 - slot_ : 0;
    const uint32_t offset = target * bankBytes();
    if (!platform::isOk(region_.eraseRange(offset, bankBytes()))) return fail(Result::Io);
    // The marker is a distinct last operation, after all body/manifest bytes.
    if (!programVerified(offset, header, 108) ||
        !programVerified(offset + 112, header + 112, 16) ||
        (size && !programVerified(offset + kHeaderBytes, manifest, size)) ||
        !programVerified(offset + 108, header + 108, 4)) return fail(Result::Io);
    ++sequence_;
    slot_ = target;
    return Result::Ok;
  }

  // Caller has authenticated repair and excluded a live/uncertain installer.
  Result repair(const Journal& idle) {
    if (!geometry() || idle.phase != Phase::Idle || idle.nextChunk ||
        !all(idle.packageHash, 32, 0) || !all(idle.transaction, 16, 0))
      return Result::Invalid;
    if (!loaded_) return Result::State;
    if (sequence_ == UINT32_MAX) return Result::State;
    const uint8_t zeros[kHeaderBytes] = {};
    for (uint32_t slot = 0; slot < 2; ++slot)
      if (!programVerified(slot * bankBytes(), zeros, sizeof(zeros))) return fail(Result::Io);
    fault_ = false;
    const Result saved = save(idle, nullptr, 0);
    if (saved != Result::Ok) return saved;
    if (!platform::isOk(region_.eraseRange((1 - slot_) * bankBytes(), bankBytes())))
      return fail(Result::Io);
    return Result::Ok;
  }

private:
  uint32_t bankBytes() const { return region_.sizeBytes() / 2; }
  bool geometry() const {
    return region_.isValid() && region_.programUnitBytes() == 1 &&
        region_.eraseUnitBytes() == 4096 && region_.sizeBytes() >= 8192 &&
        region_.sizeBytes() % (2 * region_.eraseUnitBytes()) == 0;
  }
  static bool all(const uint8_t* bytes, size_t size, uint8_t value) {
    for (size_t i = 0; i < size; ++i) if (bytes[i] != value) return false;
    return true;
  }
  static bool validJournal(const Journal& journal, size_t size) {
    if (static_cast<uint8_t>(journal.phase) > static_cast<uint8_t>(Phase::MetadataFault) ||
        static_cast<uint8_t>(journal.lastResult) > static_cast<uint8_t>(Result::Replay) ||
        journal.nextChunk > mesh::ota::v4::kMaxChunks) return false;
    if (journal.phase == Phase::Idle)
      return !size && !journal.nextChunk && all(journal.packageHash, 32, 0) &&
          all(journal.transaction, 16, 0);
    return size && !all(journal.packageHash, 32, 0) && !all(journal.transaction, 16, 0);
  }
  static bool validHeader(const uint8_t* header) {
    if (mesh::ota::v4::read32(header) != kMagic || mesh::ota::v4::read16(header + 4) != 4 ||
        mesh::ota::v4::read16(header + 6) != kHeaderBytes ||
        !mesh::ota::v4::read32(header + 8) || !all(header + 14, 2, 0) ||
        !all(header + 112, 16, 0) || mesh::ota::v4::read32(header + 108) != kMarker)
      return false;
    Journal journal;
    decode(header, journal);
    return validJournal(journal, mesh::ota::v4::read16(header + 12));
  }
  static void decode(const uint8_t* header, Journal& journal) {
    journal = Journal();
    journal.phase = static_cast<Phase>(header[16]);
    journal.lastResult = static_cast<Result>(header[17]);
    journal.nextChunk = mesh::ota::v4::read16(header + 18);
    journal.generation = mesh::ota::v4::read32(header + 20);
    std::memcpy(journal.packageHash, header + 24, 32);
    std::memcpy(journal.transaction, header + 56, 16);
  }
  bool read(uint32_t offset, uint8_t* out, size_t size) const {
    return size <= UINT32_MAX &&
        platform::isOk(region_.read(offset, out, static_cast<uint32_t>(size)));
  }
  bool blankRange(uint32_t offset, uint32_t size, bool& blank) const {
    uint8_t bytes[256];
    blank = true;
    for (uint32_t done = 0; done < size;) {
      const uint32_t count = size - done < sizeof(bytes) ? size - done : sizeof(bytes);
      if (!read(offset + done, bytes, count)) return false;
      blank = blank && all(bytes, count, 0xFF);
      done += count;
    }
    return true;
  }
  bool hashAndCrc(uint32_t offset, uint32_t size, uint8_t digest[32], uint32_t& crc) const {
    uint8_t bytes[256];
    trust::Sha256 hash;
    for (uint32_t done = 0; done < size;) {
      const uint32_t count = size - done < sizeof(bytes) ? size - done : sizeof(bytes);
      if (!read(offset + done, bytes, count)) return false;
      hash.update(bytes, count);
      crc = Crc32::compute(bytes, count, crc);
      done += count;
    }
    hash.finish(digest);
    return true;
  }
  bool programVerified(uint32_t offset, const uint8_t* bytes, size_t size) {
    uint8_t verify[256];
    for (size_t done = 0; done < size;) {
      const size_t count = size - done < sizeof(verify) ? size - done : sizeof(verify);
      if (!platform::isOk(region_.program(offset + done, bytes + done, count)) ||
          !read(offset + done, verify, count) || std::memcmp(bytes + done, verify, count))
        return false;
      done += count;
    }
    return true;
  }
  Result fail(Result result) { fault_ = true; return result; }

  platform::FlashRegion& region_;
  uint32_t sequence_ = 0;
  uint32_t slot_ = 0;
  bool loaded_ = false;
  bool fault_ = false;
};

}}
