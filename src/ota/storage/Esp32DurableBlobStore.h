#pragma once

#include "Esp32NvsApi.h"
#include "Crc32.h"
#include "ota/protocol/OtaByteStream.h"

namespace ota {
namespace storage {

enum class Esp32PersistenceStatus : uint8_t {
  Ok, Missing, Corrupt, IoError, NoSpace, GenerationExhausted, DurabilityUncertain,
  OwnershipDenied, InvalidArgument, Conflict, PartitionMismatch
};

struct Esp32PersistenceResult {
  Esp32PersistenceStatus status = Esp32PersistenceStatus::Ok;
  Esp32SdkError sdkError = kEsp32Ok;
  bool mutationMayHaveOccurred = false;
  Esp32PersistenceStatus uncertaintyCause = Esp32PersistenceStatus::Ok;
  bool ok() const { return status == Esp32PersistenceStatus::Ok; }
};

class Esp32MetadataOwner {
public:
  virtual ~Esp32MetadataOwner() = default;
  // Serializes all writers of mesh_ota, including future shared ledgers.
  virtual bool ownsNamespaceExclusively() const = 0;
};

struct Esp32DurableBlob {
  static constexpr size_t kMaxPayload = 512;
  uint8_t payload[kMaxPayload] = {};
  size_t size = 0;
  uint32_t generation = 0;
  Esp32NvsSlot slot = Esp32NvsSlot::A;
};

enum class Esp32BlobPhase : uint8_t { Prepared = 1, Committed = 2 };
enum class Esp32BlobCreation : uint8_t { ExistingOnly, ExplicitProvision };

// BE codec: magic(4), version(2), kind(1), phase(1), length(4),
// generation(4), payload, CRC32(4). Never serialize native structs.
class Esp32BlobCodec {
public:
  static constexpr size_t kOverhead = 20;
  static constexpr size_t kMaxBytes = Esp32DurableBlob::kMaxPayload + kOverhead;
  static constexpr uint32_t kMagic = 0x454f5441;  // EOTA
  static constexpr uint16_t kVersion = 1;

  static bool validKind(Esp32BlobKind kind) {
    return kind == Esp32BlobKind::Attempt || kind == Esp32BlobKind::Security ||
           kind == Esp32BlobKind::TxSequence || kind == Esp32BlobKind::RxReplay;
  }

  static size_t encode(Esp32BlobKind kind, Esp32BlobPhase phase, uint32_t generation,
                       const uint8_t* payload, size_t len, uint8_t* out, size_t capacity) {
    if (!validKind(kind) || (phase != Esp32BlobPhase::Prepared && phase != Esp32BlobPhase::Committed) ||
        generation == 0 || payload == nullptr || len == 0 ||
        len > Esp32DurableBlob::kMaxPayload || out == nullptr || capacity < len + kOverhead) return 0;
    meshcore::ota::protocol::OtaBoundedWriter writer(out, capacity);
    if (!writer.putU32(kMagic) || !writer.putU16(kVersion) ||
        !writer.putU8(static_cast<uint8_t>(kind)) || !writer.putU8(static_cast<uint8_t>(phase)) ||
        !writer.putU32(static_cast<uint32_t>(len)) || !writer.putU32(generation) ||
        !writer.putBytes(payload, len)) return 0;
    const auto crc = Crc32::computeFinalized(out, writer.size());
    if (!writer.putU32(crc)) return 0;
    return writer.size();
  }

  static bool decode(Esp32BlobKind kind, const uint8_t* bytes, size_t len,
                     Esp32DurableBlob& out, Esp32BlobPhase& phase) {
    if (!validKind(kind) || bytes == nullptr || len <= kOverhead || len > kMaxBytes) return false;
    meshcore::ota::protocol::OtaBoundedReader reader(bytes, len);
    uint32_t magic = 0, payload_len = 0, generation = 0, crc = 0;
    uint16_t version = 0;
    uint8_t stored_kind = 0, stored_phase = 0;
    if (!reader.getU32(magic) || !reader.getU16(version) || !reader.getU8(stored_kind) ||
        !reader.getU8(stored_phase) || !reader.getU32(payload_len) || !reader.getU32(generation) ||
        magic != kMagic || version != kVersion || stored_kind != static_cast<uint8_t>(kind) ||
        (stored_phase != static_cast<uint8_t>(Esp32BlobPhase::Prepared) &&
         stored_phase != static_cast<uint8_t>(Esp32BlobPhase::Committed)) ||
        generation == 0 || payload_len != len - kOverhead) return false;
    Esp32DurableBlob decoded;
    if (!reader.getBytes(decoded.payload, payload_len) || !reader.getU32(crc) ||
        crc != Crc32::computeFinalized(bytes, len - 4)) return false;
    decoded.size = payload_len;
    decoded.generation = generation;
    out = decoded;
    phase = static_cast<Esp32BlobPhase>(stored_phase);
    return true;
  }
};

class Esp32DurableBlobStore {
public:
  Esp32DurableBlobStore(Esp32NvsApi& api, const Esp32MetadataOwner& owner) : api_(api), owner_(owner) {}

#if defined(ESP32_PLATFORM)
  explicit Esp32DurableBlobStore(const Esp32MetadataOwner& owner);
#endif

  // Conservatively reserve a GC page, namespace entry, and both phase writes.
  // Stats are admission preflight, not a promise of atomic allocation across
  // unrelated namespaces; a subsequent SDK allocation failure is still fatal.
  static size_t requiredFreeEntries(size_t payload_bytes) {
    return 126 + 1 + 2 * (2 + (payload_bytes + Esp32BlobCodec::kOverhead + 31) / 32);
  }

  Esp32PersistenceResult capacity(size_t payload_bytes) const {
    if (payload_bytes == 0 || payload_bytes > Esp32DurableBlob::kMaxPayload)
      return {Esp32PersistenceStatus::InvalidArgument};
    size_t free = 0;
    const auto err = api_.freeEntries(free);
    if (err != kEsp32Ok) return {Esp32PersistenceStatus::IoError, err};
    return {free >= requiredFreeEntries(payload_bytes)
        ? Esp32PersistenceStatus::Ok : Esp32PersistenceStatus::NoSpace};
  }

  // Missing security/nonce state stays Missing. There is no zero-counter,
  // default key, erase-NVS recovery or automatic provisioning path.
  Esp32PersistenceResult load(Esp32BlobKind kind, Esp32DurableBlob& out) {
    if (uncertain_) return uncertainty_;
    if (!Esp32BlobCodec::validKind(kind)) return {Esp32PersistenceStatus::InvalidArgument};
    Esp32NvsHandle handle = 0;
    const auto err = api_.open(false, handle);
    if (err == kEsp32NvsNotFound) return {Esp32PersistenceStatus::Missing, err};
    if (err != kEsp32Ok) return {Esp32PersistenceStatus::IoError, err};
    Esp32DurableBlob a, b;
    const auto result_a = readSlot(handle, kind, Esp32NvsSlot::A, a);
    const auto result_b = readSlot(handle, kind, Esp32NvsSlot::B, b);
    api_.close(handle);
    // An unreadable/corrupt/prepared slot may be newer than the good one.
    // Never fall back to an older nonce/security/attempt record.
    if (!result_a.ok() && result_a.status != Esp32PersistenceStatus::Missing) return result_a;
    if (!result_b.ok() && result_b.status != Esp32PersistenceStatus::Missing) return result_b;
    if (!result_a.ok() && !result_b.ok()) return {Esp32PersistenceStatus::Missing};
    if (result_a.ok() && result_b.ok() && a.generation == b.generation &&
        (a.size != b.size || memcmp(a.payload, b.payload, a.size) != 0))
      return {Esp32PersistenceStatus::Corrupt};
    out = !result_b.ok() || (result_a.ok() && a.generation > b.generation) ? a : b;
    return {};
  }

  Esp32PersistenceResult save(Esp32BlobKind kind, const uint8_t* payload, size_t len,
                             Esp32BlobCreation creation = Esp32BlobCreation::ExistingOnly) {
    if (uncertain_) return uncertainty_;
    if (!owner_.ownsNamespaceExclusively()) return {Esp32PersistenceStatus::OwnershipDenied};
    if (!Esp32BlobCodec::validKind(kind) || payload == nullptr || len == 0 ||
        len > Esp32DurableBlob::kMaxPayload ||
        (creation != Esp32BlobCreation::ExistingOnly && creation != Esp32BlobCreation::ExplicitProvision))
      return {Esp32PersistenceStatus::InvalidArgument};
    Esp32DurableBlob previous;
    const auto loaded = load(kind, previous);
    if (!loaded.ok() && (loaded.status != Esp32PersistenceStatus::Missing ||
                        creation != Esp32BlobCreation::ExplicitProvision)) return loaded;
    if (loaded.ok() && previous.generation == UINT32_MAX)
      return {Esp32PersistenceStatus::GenerationExhausted};
    const auto room = capacity(len);
    if (!room.ok()) return room;
    const uint32_t generation = loaded.ok() ? previous.generation + 1 : 1;
    const auto slot = loaded.ok() && previous.slot == Esp32NvsSlot::A ? Esp32NvsSlot::B : Esp32NvsSlot::A;
    uint8_t encoded[Esp32BlobCodec::kMaxBytes];
    const Esp32BlobPhase phases[] = {Esp32BlobPhase::Prepared, Esp32BlobPhase::Committed};
    for (const auto phase : phases) {
      const size_t encoded_len = Esp32BlobCodec::encode(
          kind, phase, generation, payload, len, encoded, sizeof(encoded));
      const auto written = writeAndReadback(kind, slot, encoded, encoded_len);
      if (!written.ok()) {
        uncertain_ = true;
        uncertainty_ = {Esp32PersistenceStatus::DurabilityUncertain, written.sdkError, true, written.status};
        return uncertainty_;
      }
    }
    return {Esp32PersistenceStatus::Ok, kEsp32Ok, true};
  }

private:
  Esp32PersistenceResult readSlot(Esp32NvsHandle handle, Esp32BlobKind kind,
                                 Esp32NvsSlot slot, Esp32DurableBlob& out) const {
    size_t len = 0;
    auto err = api_.get(handle, kind, slot, nullptr, len);
    if (err == kEsp32NvsNotFound) return {Esp32PersistenceStatus::Missing, err};
    if (err == kEsp32NvsTypeMismatch || err == kEsp32NvsInvalidLength)
      return {Esp32PersistenceStatus::Corrupt, err};
    if (err != kEsp32Ok) return {Esp32PersistenceStatus::IoError, err};
    if (len <= Esp32BlobCodec::kOverhead || len > Esp32BlobCodec::kMaxBytes)
      return {Esp32PersistenceStatus::Corrupt};
    uint8_t bytes[Esp32BlobCodec::kMaxBytes];
    const size_t expected_len = len;
    err = api_.get(handle, kind, slot, bytes, len);
    if (err == kEsp32NvsNotFound || err == kEsp32NvsTypeMismatch || err == kEsp32NvsInvalidLength)
      return {Esp32PersistenceStatus::Corrupt, err};
    if (err != kEsp32Ok) return {Esp32PersistenceStatus::IoError, err};
    Esp32BlobPhase phase = Esp32BlobPhase::Prepared;
    if (len != expected_len || !Esp32BlobCodec::decode(kind, bytes, len, out, phase))
      return {Esp32PersistenceStatus::Corrupt};
    out.slot = slot;
    if (phase == Esp32BlobPhase::Prepared)
      return {Esp32PersistenceStatus::DurabilityUncertain, kEsp32Ok, true};
    return {};
  }

  Esp32PersistenceResult writeAndReadback(Esp32BlobKind kind, Esp32NvsSlot slot,
                                        const uint8_t* bytes, size_t len) {
    if (!owner_.ownsNamespaceExclusively()) return {Esp32PersistenceStatus::OwnershipDenied};
    Esp32NvsHandle handle = 0;
    auto err = api_.open(true, handle);
    if (err != kEsp32Ok) return {Esp32PersistenceStatus::IoError, err};
    err = api_.set(handle, kind, slot, bytes, len);
    if (err == kEsp32Ok) err = api_.commit(handle);
    api_.close(handle);
    if (err != kEsp32Ok) return {Esp32PersistenceStatus::IoError, err, true};
    err = api_.open(false, handle);
    if (err != kEsp32Ok) return {Esp32PersistenceStatus::IoError, err, true};
    uint8_t readback[Esp32BlobCodec::kMaxBytes];
    size_t read_len = sizeof(readback);
    err = api_.get(handle, kind, slot, readback, read_len);
    api_.close(handle);
    if (err != kEsp32Ok) return {Esp32PersistenceStatus::IoError, err, true};
    if (read_len != len || memcmp(bytes, readback, len) != 0)
      return {Esp32PersistenceStatus::Corrupt, kEsp32Ok, true};
    return {Esp32PersistenceStatus::Ok, kEsp32Ok, true};
  }

  Esp32NvsApi& api_;
  const Esp32MetadataOwner& owner_;
  bool uncertain_ = false;
  Esp32PersistenceResult uncertainty_{Esp32PersistenceStatus::DurabilityUncertain};
};

}  // namespace storage
}  // namespace ota
