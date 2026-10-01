#pragma once

#include <algorithm>
#include <vector>
#include <ota/storage/Esp32PartitionApi.h>

namespace ota {
namespace test {

using namespace ota::storage;

enum class FaultTiming { None, Before, Torn, After };

class Esp32Owners final : public Esp32UpdateOwner {
public:
  Esp32UpdateOwnership flash = Esp32UpdateOwnership::ExclusiveStorage;
  Esp32UpdateOwnership ownership(const Esp32PartitionIdentity&) const override { return flash; }
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

}  // namespace test
}  // namespace ota
