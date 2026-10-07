#include "Esp32FlashAdapter.h"

#if defined(ESP32_PLATFORM)
#include <esp_flash.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>

namespace ota {
namespace storage {
namespace {

Esp32PartitionIdentity identity(const esp_partition_t& partition) {
  Esp32PartitionIdentity out;
  out.address = partition.address;
  out.size = partition.size;
  out.type = static_cast<uint8_t>(partition.type);
  out.subtype = static_cast<uint8_t>(partition.subtype);
  memcpy(out.label, partition.label, sizeof(out.label));
  out.encrypted = partition.encrypted;
  out.defaultFlash = partition.flash_chip == esp_flash_default_chip;
  return out;
}

const esp_partition_t* resolve(const Esp32PartitionIdentity& requested) {
  // Do not let callers of the SDK boundary turn it into unrestricted flash.
  if (!esp32PartitionEquals(requested, Esp32S3PartitionLayout::entry(2)) &&
      !esp32PartitionEquals(requested, Esp32S3PartitionLayout::entry(3))) return nullptr;
  const auto* partition = esp_partition_find_first(
      ESP_PARTITION_TYPE_APP, static_cast<esp_partition_subtype_t>(requested.subtype), requested.label);
  if (partition == nullptr || !esp32PartitionEquals(identity(*partition), requested) ||
      partition == esp_ota_get_running_partition() ||
      partition == esp_ota_get_boot_partition()) return nullptr;
  return partition;
}

bool inRange(const Esp32PartitionIdentity& partition, uint32_t offset, uint32_t len) {
  return offset <= partition.size && len <= partition.size - offset;
}

}  // namespace

Esp32SdkError Esp32IdfPartitionApi::inspect(Esp32PartitionSnapshot& out) const {
  Esp32PartitionSnapshot fresh;
  esp_err_t err = esp_flash_get_size(esp_flash_default_chip, &fresh.flashSize);
  if (err != ESP_OK) return err;
  // get_size reports the image-header limit, not the physical chip capacity.
  err = esp_flash_get_physical_size(esp_flash_default_chip, &fresh.physicalFlashSize);
  if (err != ESP_OK) return err;
  auto iterator = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, nullptr);
  while (iterator != nullptr) {
    if (fresh.count == Esp32PartitionSnapshot::kPartitionCount) {
      esp_partition_iterator_release(iterator);
      return ESP_ERR_INVALID_SIZE;
    }
    fresh.table[fresh.count++] = identity(*esp_partition_get(iterator));
    iterator = esp_partition_next(iterator);
  }
  const auto* running = esp_ota_get_running_partition();
  const auto* boot = esp_ota_get_boot_partition();
  if (running == nullptr || boot == nullptr) return ESP_ERR_NOT_FOUND;
  const auto* next = esp_ota_get_next_update_partition(running);
  if (next == nullptr) return ESP_ERR_NOT_FOUND;
  fresh.running = identity(*running);
  fresh.boot = identity(*boot);
  fresh.next = identity(*next);
  for (size_t slot = 0; slot < 2; ++slot) {
    const auto* app = esp_partition_find_first(
        ESP_PARTITION_TYPE_APP, static_cast<esp_partition_subtype_t>(0x10 + slot), nullptr);
    if (app == nullptr) return ESP_ERR_NOT_FOUND;
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    err = esp_ota_get_state_partition(app, &state);
    // No OTA record for an unused/stock slot is a distinct SDK state, not
    // an I/O error. All OTHER failures retain their original esp_err_t.
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) return err;
    fresh.appStates[slot] = err == ESP_ERR_NOT_FOUND
        ? Esp32ImageState::Undefined : static_cast<Esp32ImageState>(state);
  }
  out = fresh;
  return ESP_OK;
}

Esp32SdkError Esp32IdfPartitionApi::read(const Esp32PartitionIdentity& partition,
                                       uint32_t offset, uint8_t* data, uint32_t len) const {
  const auto* sdk_partition = resolve(partition);
  if (sdk_partition == nullptr || !inRange(partition, offset, len) || (data == nullptr && len != 0))
    return ESP_ERR_INVALID_ARG;
  return esp_partition_read(sdk_partition, offset, data, len);
}

Esp32SdkError Esp32IdfPartitionApi::write(const Esp32PartitionIdentity& partition,
                                        uint32_t offset, const uint8_t* data, uint32_t len) {
  const auto* sdk_partition = resolve(partition);
  if (sdk_partition == nullptr || !inRange(partition, offset, len) || (data == nullptr && len != 0))
    return ESP_ERR_INVALID_ARG;
  return esp_partition_write(sdk_partition, offset, data, len);
}

Esp32SdkError Esp32IdfPartitionApi::erase(const Esp32PartitionIdentity& partition,
                                        uint32_t offset, uint32_t len) {
  const auto* sdk_partition = resolve(partition);
  if (sdk_partition == nullptr || !inRange(partition, offset, len) ||
      offset % 4096 != 0 || len % 4096 != 0) return ESP_ERR_INVALID_ARG;
  return esp_partition_erase_range(sdk_partition, offset, len);
}

}  // namespace storage

namespace platform {

Esp32FlashAdapter::Esp32FlashAdapter(const storage::Esp32UpdateOwner& owner)
    : Esp32FlashAdapter([]() -> storage::Esp32IdfPartitionApi& {
        static storage::Esp32IdfPartitionApi sdk;
        return sdk;
      }(), owner) {}

}  // namespace platform
}  // namespace ota
#endif
