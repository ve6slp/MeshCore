#pragma once

// A FlashDevice capability for ONE inactive app partition, not whole flash.
// Offsets are partition-relative. Stock Arduino installation is deliberately
// unavailable: this adapter never changes boot selection or validates a trial.

#include <stdint.h>
#include <string.h>
#include "ota/platform/FlashDevice.h"
#include "ota/platform/FlashTypes.h"
#include "ota/storage/Esp32PartitionApi.h"

namespace ota {
namespace platform {

class Esp32FlashAdapter : public FlashDevice {
public:
  enum class Refusal : uint8_t {
    None, Unbound, Table, Partition, Running, BootSelection, Trial, Ownership,
    Capacity, Encrypted, Bounds, Argument, Alignment, NorViolation, Sdk
  };

  // Compatibility geometry-only constructor. It still cannot perform I/O.
  Esp32FlashAdapter(uint32_t total_size_bytes, uint32_t erase_unit_bytes, uint32_t program_unit_bytes)
      : total_size_bytes_(total_size_bytes),
        erase_unit_bytes_(erase_unit_bytes),
        program_unit_bytes_(program_unit_bytes) {}

  Esp32FlashAdapter(storage::Esp32PartitionApi& api, const storage::Esp32UpdateOwner& owner)
      : api_(&api), owner_(&owner) {}

#if defined(ESP32_PLATFORM)
  // Production entry point: always binds actual IDF, never an injected fake.
  explicit Esp32FlashAdapter(const storage::Esp32UpdateOwner& owner);
#endif

  // A persisted identity is mandatory on resume. It is compared with a FRESH
  // SDK-selected partition, never used to choose a partition by label alone.
  FlashStatus bind(uint32_t required_bytes,
                   const storage::Esp32PartitionIdentity* persisted = nullptr) {
    bound_ = false;
    if (api_ == nullptr) return reject(FlashStatus::Unsupported, Refusal::Unbound);
    total_size_bytes_ = 0;
    if (required_bytes == 0) return reject(FlashStatus::InvalidArgument, Refusal::Argument);
    storage::Esp32PartitionSnapshot snapshot;
    const auto err = api_->inspect(snapshot);
    if (err != storage::kEsp32Ok) return sdkFailure(err);
    FlashStatus status = validate(snapshot);
    if (!isOk(status)) return status;
    if (persisted != nullptr && !storage::esp32PartitionEquals(*persisted, snapshot.next))
      return reject(FlashStatus::InvalidArgument, Refusal::Partition);
    if (required_bytes > snapshot.next.size)
      return reject(FlashStatus::OutOfRange, Refusal::Capacity);
    partition_ = snapshot.next;
    total_size_bytes_ = partition_.size;
    bound_ = true;
    return success();
  }

  bool isBound() const { return bound_; }
  void unbind() {
    bound_ = false;
    if (api_ != nullptr) total_size_bytes_ = 0;
  }
  const storage::Esp32PartitionIdentity& partition() const { return partition_; }
  storage::Esp32SdkError lastSdkError() const { return last_sdk_error_; }
  Refusal lastRefusal() const { return last_refusal_; }
  static constexpr bool installationAvailable() { return false; }

  uint32_t totalSizeBytes() const override { return total_size_bytes_; }
  uint32_t eraseUnitBytes() const override { return erase_unit_bytes_; }
  uint32_t programUnitBytes() const override { return program_unit_bytes_; }

  FlashStatus eraseSector(uint32_t offset) override {
    FlashStatus status = check(offset, erase_unit_bytes_);
    if (!isOk(status)) return status;
    if (offset % erase_unit_bytes_ != 0)
      return reject(FlashStatus::Unaligned, Refusal::Alignment);
    const auto err = api_->erase(partition_, offset, erase_unit_bytes_);
    return err == storage::kEsp32Ok ? success() : sdkFailure(err);
  }

  FlashStatus program(uint32_t offset, const uint8_t* data, uint32_t len) override {
    FlashStatus status = check(offset, len);
    if (!isOk(status)) return status;
    if (data == nullptr && len != 0)
      return reject(FlashStatus::InvalidArgument, Refusal::Argument);
    // Unencrypted esp_partition_write is byte-addressable. Check the ENTIRE
    // range before changing any bits; IDF alone silently ANDs illegal writes.
    uint8_t previous[128];
    for (uint32_t done = 0; done < len;) {
      const uint32_t step = len - done < sizeof(previous) ? len - done : sizeof(previous);
      const auto err = api_->read(partition_, offset + done, previous, step);
      if (err != storage::kEsp32Ok) return sdkFailure(err);
      for (uint32_t i = 0; i < step; ++i)
        if ((previous[i] & data[done + i]) != data[done + i])
          return reject(FlashStatus::PartialProgramViolation, Refusal::NorViolation);
      done += step;
    }
    if (len == 0) return success();
    const auto err = api_->write(partition_, offset, data, len);
    return err == storage::kEsp32Ok ? success() : sdkFailure(err);
  }

  FlashStatus read(uint32_t offset, uint8_t* data, uint32_t len) const override {
    FlashStatus status = check(offset, len);
    if (!isOk(status)) return status;
    if (data == nullptr && len != 0)
      return reject(FlashStatus::InvalidArgument, Refusal::Argument);
    if (len == 0) return success();
    const auto err = api_->read(partition_, offset, data, len);
    return err == storage::kEsp32Ok ? success() : sdkFailure(err);
  }

  static constexpr bool hasHardwareBackend() {
#if defined(ESP32_PLATFORM)
    return true;
#else
    return false;
#endif
  }

private:
  FlashStatus validate(const storage::Esp32PartitionSnapshot& s) const {
    if (s.next.encrypted || s.running.encrypted)
      return reject(FlashStatus::Unsupported, Refusal::Encrypted);
    if (!storage::Esp32S3PartitionLayout::matches(s))
      return reject(FlashStatus::InvalidArgument, Refusal::Table);
    const auto app0 = storage::Esp32S3PartitionLayout::entry(2);
    const auto app1 = storage::Esp32S3PartitionLayout::entry(3);
    const bool running0 = storage::esp32PartitionEquals(s.running, app0);
    const bool running1 = storage::esp32PartitionEquals(s.running, app1);
    if (!running0 && !running1) return reject(FlashStatus::InvalidArgument, Refusal::Running);
    if (storage::esp32PartitionEquals(s.running, s.next))
      return reject(FlashStatus::InvalidArgument, Refusal::Running);
    if (!storage::esp32PartitionEquals(s.next, running0 ? app1 : app0))
      return reject(FlashStatus::InvalidArgument, Refusal::Partition);
    if (!storage::esp32PartitionEquals(s.boot, s.running))
      return reject(FlashStatus::IoError, Refusal::BootSelection);
    for (const auto state : s.appStates) {
      if (state == storage::Esp32ImageState::New || state == storage::Esp32ImageState::PendingVerify)
        return reject(FlashStatus::IoError, Refusal::Trial);
      if (state != storage::Esp32ImageState::Valid && state != storage::Esp32ImageState::Invalid &&
          state != storage::Esp32ImageState::Aborted && state != storage::Esp32ImageState::Undefined)
        return reject(FlashStatus::IoError, Refusal::Trial);
    }
    const auto running_state = s.appStates[running0 ? 0 : 1];
    if (running_state == storage::Esp32ImageState::Invalid ||
        running_state == storage::Esp32ImageState::Aborted)
      return reject(FlashStatus::IoError, Refusal::Trial);
    if (owner_ == nullptr ||
        owner_->ownership(s.next) != storage::Esp32UpdateOwnership::ExclusiveStorage)
      return reject(FlashStatus::IoError, Refusal::Ownership);
    return success();
  }

  FlashStatus check(uint32_t offset, uint32_t len) const {
    if (!bound_ || api_ == nullptr) return reject(FlashStatus::Unsupported, Refusal::Unbound);
    if (offset > partition_.size || len > partition_.size - offset)
      return reject(FlashStatus::OutOfRange, Refusal::Bounds);
    storage::Esp32PartitionSnapshot snapshot;
    const auto err = api_->inspect(snapshot);
    if (err != storage::kEsp32Ok) return sdkFailure(err);
    const auto status = validate(snapshot);
    if (!isOk(status)) return status;
    if (!storage::esp32PartitionEquals(partition_, snapshot.next))
      return reject(FlashStatus::InvalidArgument, Refusal::Partition);
    return success();
  }

  FlashStatus reject(FlashStatus status, Refusal refusal) const {
    last_sdk_error_ = storage::kEsp32Ok;
    last_refusal_ = refusal;
    return status;
  }
  FlashStatus sdkFailure(storage::Esp32SdkError err) const {
    last_sdk_error_ = err;
    last_refusal_ = Refusal::Sdk;
    return FlashStatus::IoError;
  }
  FlashStatus success() const { return reject(FlashStatus::Ok, Refusal::None); }

  storage::Esp32PartitionApi* api_ = nullptr;
  const storage::Esp32UpdateOwner* owner_ = nullptr;
  storage::Esp32PartitionIdentity partition_;
  uint32_t total_size_bytes_ = 0;
  uint32_t erase_unit_bytes_ = 4096;
  uint32_t program_unit_bytes_ = 1;
  bool bound_ = false;
  mutable storage::Esp32SdkError last_sdk_error_ = storage::kEsp32Ok;
  mutable Refusal last_refusal_ = Refusal::Unbound;
};

}  // namespace platform
}  // namespace ota
