#pragma once

#include "Esp32PartitionApi.h"

namespace ota {
namespace storage {

enum class Esp32BlobKind : uint8_t { Attempt = 1, Security = 2, TxSequence = 3, RxReplay = 4 };
enum class Esp32NvsSlot : uint8_t { A, B };
using Esp32NvsHandle = uint32_t;

// Every API operation is confined to nvs / mesh_ota. No init, erase, format,
// arbitrary namespace/key, or application partition access is exposed here.
class Esp32NvsApi {
public:
  virtual ~Esp32NvsApi() = default;
  virtual Esp32SdkError freeEntries(size_t& out) const = 0;
  virtual Esp32SdkError open(bool writable, Esp32NvsHandle& out) = 0;
  virtual void close(Esp32NvsHandle handle) = 0;
  virtual Esp32SdkError get(Esp32NvsHandle, Esp32BlobKind, Esp32NvsSlot,
                           uint8_t* out, size_t& len) const = 0;
  virtual Esp32SdkError set(Esp32NvsHandle, Esp32BlobKind, Esp32NvsSlot,
                           const uint8_t* data, size_t len) = 0;
  virtual Esp32SdkError commit(Esp32NvsHandle) = 0;
};

#if defined(ESP32_PLATFORM)
class Esp32IdfNvsApi final : public Esp32NvsApi {
public:
  Esp32SdkError freeEntries(size_t& out) const override;
  Esp32SdkError open(bool writable, Esp32NvsHandle& out) override;
  void close(Esp32NvsHandle handle) override;
  Esp32SdkError get(Esp32NvsHandle, Esp32BlobKind, Esp32NvsSlot, uint8_t*, size_t&) const override;
  Esp32SdkError set(Esp32NvsHandle, Esp32BlobKind, Esp32NvsSlot, const uint8_t*, size_t) override;
  Esp32SdkError commit(Esp32NvsHandle) override;
};
#endif

}  // namespace storage
}  // namespace ota
