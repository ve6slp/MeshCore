#include "Esp32NvsApi.h"
#include "Esp32AttemptStore.h"

#if defined(ESP32_PLATFORM)
#include <nvs.h>
#include <esp_partition.h>
#include <esp_flash.h>

namespace ota {
namespace storage {
namespace {

const char* key(Esp32BlobKind kind, Esp32NvsSlot slot) {
  if (slot != Esp32NvsSlot::A && slot != Esp32NvsSlot::B) return nullptr;
  switch (kind) {
    case Esp32BlobKind::Attempt: return slot == Esp32NvsSlot::A ? "attempt_a" : "attempt_b";
    case Esp32BlobKind::Security: return slot == Esp32NvsSlot::A ? "security_a" : "security_b";
    case Esp32BlobKind::TxSequence: return slot == Esp32NvsSlot::A ? "txseq_a" : "txseq_b";
    case Esp32BlobKind::RxReplay: return slot == Esp32NvsSlot::A ? "rxreplay_a" : "rxreplay_b";
  }
  return nullptr;
}

bool validNvsPartition() {
  const auto* nvs = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, "nvs");
  return nvs != nullptr && nvs->address == 0x9000 && nvs->size == 0x5000 &&
         !nvs->encrypted && nvs->flash_chip == esp_flash_default_chip;
}

}  // namespace

Esp32SdkError Esp32IdfNvsApi::freeEntries(size_t& out) const {
  if (!validNvsPartition()) return ESP_ERR_INVALID_ARG;
  nvs_stats_t stats = {};
  const auto err = nvs_get_stats("nvs", &stats);
  if (err == ESP_OK) out = stats.free_entries;
  return err;
}

Esp32SdkError Esp32IdfNvsApi::open(bool writable, Esp32NvsHandle& out) {
  if (!validNvsPartition()) return ESP_ERR_INVALID_ARG;
  return nvs_open_from_partition("nvs", "mesh_ota", writable ? NVS_READWRITE : NVS_READONLY, &out);
}

void Esp32IdfNvsApi::close(Esp32NvsHandle handle) { nvs_close(handle); }

Esp32SdkError Esp32IdfNvsApi::get(Esp32NvsHandle handle, Esp32BlobKind kind, Esp32NvsSlot slot,
                                 uint8_t* out, size_t& len) const {
  const auto* name = key(kind, slot);
  if (name == nullptr) return ESP_ERR_INVALID_ARG;
  return nvs_get_blob(handle, name, out, &len);
}

Esp32SdkError Esp32IdfNvsApi::set(Esp32NvsHandle handle, Esp32BlobKind kind, Esp32NvsSlot slot,
                                 const uint8_t* data, size_t len) {
  const auto* name = key(kind, slot);
  if (name == nullptr || data == nullptr || len == 0) return ESP_ERR_INVALID_ARG;
  return nvs_set_blob(handle, name, data, len);
}

Esp32SdkError Esp32IdfNvsApi::commit(Esp32NvsHandle handle) { return nvs_commit(handle); }

Esp32DurableBlobStore::Esp32DurableBlobStore(const Esp32MetadataOwner& owner)
    : Esp32DurableBlobStore([]() -> Esp32IdfNvsApi& {
        static Esp32IdfNvsApi sdk;
        return sdk;
      }(), owner) {}

}  // namespace storage
}  // namespace ota
#endif
