#pragma once

#include <ota/platform/FlashDevice.h>
#include <ota/storage/Esp32PartitionApi.h>

namespace ota { namespace platform {

// One fixed journal, not a second APP writer. The capability exposes only the
// final 16 KiB of app0; neither image slot, NVS, otadata nor userdata is reachable.
class Esp32OtaMetadataAdapter final : public FlashDevice {
public:
  static constexpr uint32_t kBytes = 16384;
  static constexpr uint32_t kOffset = 0x330000 - kBytes;
  explicit Esp32OtaMetadataAdapter(storage::Esp32PartitionApi& api) : api_(api) {}
  uint32_t totalSizeBytes() const override { return kBytes; }
  uint32_t eraseUnitBytes() const override { return 4096; }
  uint32_t programUnitBytes() const override { return 1; }
  FlashStatus read(uint32_t offset, uint8_t* out, uint32_t size) const override {
    const FlashStatus checked = check(offset, size);
    if (!isOk(checked) || (!out && size)) return !isOk(checked) ? checked : FlashStatus::InvalidArgument;
    return api_.read(storage::Esp32S3PartitionLayout::entry(2), kOffset + offset, out, size) ==
        storage::kEsp32Ok ? FlashStatus::Ok : FlashStatus::IoError;
  }
  FlashStatus program(uint32_t offset, const uint8_t* bytes, uint32_t size) override {
    const FlashStatus checked = check(offset, size);
    if (!isOk(checked) || (!bytes && size)) return !isOk(checked) ? checked : FlashStatus::InvalidArgument;
    uint8_t previous[128];
    for (uint32_t done = 0; done < size;) {
      const uint32_t count = size - done < sizeof(previous) ? size - done : sizeof(previous);
      if (!isOk(read(offset + done, previous, count))) return FlashStatus::IoError;
      for (uint32_t i = 0; i < count; ++i)
        if ((previous[i] & bytes[done + i]) != bytes[done + i]) return FlashStatus::PartialProgramViolation;
      done += count;
    }
    return api_.write(storage::Esp32S3PartitionLayout::entry(2), kOffset + offset, bytes, size) ==
        storage::kEsp32Ok ? FlashStatus::Ok : FlashStatus::IoError;
  }
  FlashStatus eraseSector(uint32_t offset) override {
    const FlashStatus checked = check(offset, 4096);
    if (!isOk(checked)) return checked;
    if (offset % 4096) return FlashStatus::Unaligned;
    return api_.erase(storage::Esp32S3PartitionLayout::entry(2), kOffset + offset, 4096) ==
        storage::kEsp32Ok ? FlashStatus::Ok : FlashStatus::IoError;
  }
private:
  FlashStatus check(uint32_t offset, uint32_t size) const {
    if (offset > kBytes || size > kBytes - offset) return FlashStatus::OutOfRange;
    storage::Esp32PartitionSnapshot snapshot;
    if (api_.inspect(snapshot) != storage::kEsp32Ok) return FlashStatus::IoError;
    if (!storage::Esp32S3PartitionLayout::matches(snapshot)) return FlashStatus::InvalidArgument;
    return FlashStatus::Ok;
  }
  storage::Esp32PartitionApi& api_;
};

}}
