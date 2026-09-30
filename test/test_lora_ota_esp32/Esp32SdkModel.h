#pragma once

#include <algorithm>
#include <map>
#include <string>
#include <vector>
#include <ota/storage/Esp32NvsApi.h>

namespace ota {
namespace test {

using namespace ota::storage;

enum class FaultTiming { None, Before, Torn, After };

class Esp32Owners final : public Esp32UpdateOwner, public Esp32MetadataOwner {
public:
  Esp32UpdateOwnership flash = Esp32UpdateOwnership::ExclusiveStorage;
  bool metadata = true;
  Esp32UpdateOwnership ownership(const Esp32PartitionIdentity&) const override { return flash; }
  bool ownsNamespaceExclusively() const override { return metadata; }
};

class Esp32PartitionModel final : public Esp32PartitionApi {
public:
  Esp32PartitionSnapshot snapshot;
  std::vector<uint8_t> bytes = std::vector<uint8_t>(0x800000, 0xa5);
  std::vector<uint32_t> erasedOffsets;
  uint32_t writeCalls = 0;
  mutable uint32_t readCalls = 0;
  Esp32SdkError inspectError = kEsp32Ok;
  Esp32SdkError readError = kEsp32Ok;
  Esp32SdkError eraseError = kEsp32Ok;
  FaultTiming writeFault = FaultTiming::None;
  uint32_t tornBytes = 0;
  Esp32SdkError writeError = -1;  // ESP_FAIL

  explicit Esp32PartitionModel(bool running_app1 = false) {
    snapshot.flashSize = static_cast<uint32_t>(bytes.size());
    snapshot.physicalFlashSize = static_cast<uint32_t>(bytes.size());
    snapshot.count = Esp32PartitionSnapshot::kPartitionCount;
    for (size_t i = 0; i < snapshot.count; ++i) snapshot.table[i] = Esp32S3PartitionLayout::entry(i);
    snapshot.running = Esp32S3PartitionLayout::entry(running_app1 ? 3 : 2);
    snapshot.boot = snapshot.running;
    snapshot.next = Esp32S3PartitionLayout::entry(running_app1 ? 2 : 3);
    snapshot.appStates[0] = Esp32ImageState::Valid;
    snapshot.appStates[1] = Esp32ImageState::Valid;
    std::fill(bytes.begin() + snapshot.next.address,
              bytes.begin() + snapshot.next.address + snapshot.next.size, 0xff);
  }

  Esp32SdkError inspect(Esp32PartitionSnapshot& out) const override {
    if (inspectError != kEsp32Ok) return inspectError;
    out = snapshot;
    return kEsp32Ok;
  }
  Esp32SdkError read(const Esp32PartitionIdentity& p, uint32_t offset,
                    uint8_t* out, uint32_t len) const override {
    ++readCalls;
    if (readError != kEsp32Ok) return readError;
    if (!valid(p, offset, len)) return kEsp32InvalidArgument;
    memcpy(out, bytes.data() + p.address + offset, len);
    return kEsp32Ok;
  }
  Esp32SdkError write(const Esp32PartitionIdentity& p, uint32_t offset,
                     const uint8_t* data, uint32_t len) override {
    ++writeCalls;
    if (!valid(p, offset, len)) return kEsp32InvalidArgument;
    if (writeFault == FaultTiming::Before) return writeError;
    const uint32_t applied = writeFault == FaultTiming::Torn ? std::min(tornBytes, len) : len;
    // IDF does not diagnose a 0->1 request; physical NOR simply ANDs it.
    for (uint32_t i = 0; i < applied; ++i) bytes[p.address + offset + i] &= data[i];
    return writeFault == FaultTiming::None ? kEsp32Ok : writeError;
  }
  Esp32SdkError erase(const Esp32PartitionIdentity& p, uint32_t offset, uint32_t len) override {
    if (!valid(p, offset, len) || offset % 4096 != 0 || len != 4096) return kEsp32InvalidArgument;
    if (eraseError != kEsp32Ok) return eraseError;
    erasedOffsets.push_back(offset);
    std::fill(bytes.begin() + p.address + offset, bytes.begin() + p.address + offset + len, 0xff);
    return kEsp32Ok;
  }

private:
  bool valid(const Esp32PartitionIdentity& p, uint32_t offset, uint32_t len) const {
    return esp32PartitionEquals(p, snapshot.next) && p.type == 0 &&
           !esp32PartitionEquals(p, snapshot.running) &&
           offset <= p.size && len <= p.size - offset;
  }
};

class Esp32NvsModel final : public Esp32NvsApi {
public:
  using Key = std::pair<Esp32BlobKind, Esp32NvsSlot>;
  std::map<Key, std::vector<uint8_t>> durable;
  std::map<std::string, std::vector<uint8_t>> unrelated{
      {"meshcore/settings", {0x12, 0x34, 0x56}}, {"credentials/key", {0x82, 0x23, 0x41}}};
  std::vector<std::string> trace;
  bool namespaceExists = false;
  // IDF 4.4 writes during set_blob; commit is still mandatory. Also exercise
  // deferred SDK semantics so the storage algorithm cannot rely on that.
  bool immediate = true;
  size_t free = 500;
  Esp32SdkError statsError = kEsp32Ok;
  Esp32SdkError openError = kEsp32Ok;
  mutable Esp32SdkError getError = kEsp32Ok;
  uint32_t setCalls = 0;
  uint32_t commitCalls = 0;
  mutable uint32_t getCalls = 0;
  uint32_t failSetAt = 0;
  uint32_t failCommitAt = 0;
  uint32_t failGetAt = 0;
  uint32_t badReadbackAt = 0;
  FaultTiming setTiming = FaultTiming::Before;
  FaultTiming commitTiming = FaultTiming::Before;
  size_t tornBytes = 0;
  Esp32SdkError faultError = -1;

  Esp32SdkError freeEntries(size_t& out) const override {
    if (statsError != kEsp32Ok) return statsError;
    out = free;
    return kEsp32Ok;
  }
  Esp32SdkError open(bool writable, Esp32NvsHandle& out) override {
    trace.push_back(writable ? "open-rw" : "open-ro");
    if (openError != kEsp32Ok) return openError;
    if (!namespaceExists && !writable) return kEsp32NvsNotFound;
    if (writable) namespaceExists = true;
    out = ++nextHandle_;
    handles_[out].writable = writable;
    return kEsp32Ok;
  }
  void close(Esp32NvsHandle handle) override {
    trace.push_back("close");
    handles_.erase(handle);
  }
  Esp32SdkError get(Esp32NvsHandle handle, Esp32BlobKind kind, Esp32NvsSlot slot,
                   uint8_t* out, size_t& len) const override {
    ++getCalls;
    if (handles_.count(handle) == 0) return 0x1107;
    if (getError != kEsp32Ok) return getError;
    if (failGetAt == getCalls) return faultError;
    const auto found = durable.find({kind, slot});
    if (found == durable.end()) return kEsp32NvsNotFound;
    const auto& blob = found->second;
    if (out != nullptr && len < blob.size()) return kEsp32NvsInvalidLength;
    if (out != nullptr) {
      memcpy(out, blob.data(), blob.size());
      if (badReadbackAt == getCalls && !blob.empty()) out[blob.size() - 1] ^= 0x01;
    }
    len = blob.size();
    return kEsp32Ok;
  }
  Esp32SdkError set(Esp32NvsHandle handle, Esp32BlobKind kind, Esp32NvsSlot slot,
                   const uint8_t* data, size_t len) override {
    ++setCalls;
    trace.push_back("set");
    if (handles_.count(handle) == 0 || !handles_.at(handle).writable) return 0x1104;
    const bool fault = failSetAt == setCalls;
    if (fault && setTiming == FaultTiming::Before) return faultError;
    std::vector<uint8_t> blob(data, data + len);
    if (fault && setTiming == FaultTiming::Torn) blob.resize(std::min(tornBytes, len));
    if (immediate || fault) durable[{kind, slot}] = blob;
    else handles_.at(handle).pending[{kind, slot}] = blob;
    return fault ? faultError : kEsp32Ok;
  }
  Esp32SdkError commit(Esp32NvsHandle handle) override {
    ++commitCalls;
    trace.push_back("commit");
    const bool fault = failCommitAt == commitCalls;
    if (fault && commitTiming == FaultTiming::Before) return faultError;
    if (handles_.count(handle) == 0) return 0x1107;
    for (const auto& kv : handles_.at(handle).pending) durable[kv.first] = kv.second;
    handles_.at(handle).pending.clear();
    return fault ? faultError : kEsp32Ok;
  }

  void clearFaults() {
    failSetAt = failCommitAt = failGetAt = badReadbackAt = 0;
    getError = kEsp32Ok;
  }

private:
  struct Handle {
    bool writable = false;
    std::map<Key, std::vector<uint8_t>> pending;
  };
  std::map<Esp32NvsHandle, Handle> handles_;
  Esp32NvsHandle nextHandle_ = 0;
};

}  // namespace test
}  // namespace ota
