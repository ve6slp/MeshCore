#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#if defined(ESP32_PLATFORM)
#include <esp_err.h>
#endif

namespace ota {
namespace storage {

#if defined(ESP32_PLATFORM)
using Esp32SdkError = esp_err_t;
#else
using Esp32SdkError = int32_t;
#endif

// Values are ESP-IDF errors, including in the native SDK model.
constexpr Esp32SdkError kEsp32Ok = 0;
constexpr Esp32SdkError kEsp32InvalidArgument = 0x102;
constexpr Esp32SdkError kEsp32InvalidSize = 0x104;
constexpr Esp32SdkError kEsp32NotFound = 0x105;
constexpr Esp32SdkError kEsp32NvsNotFound = 0x1102;
constexpr Esp32SdkError kEsp32NvsTypeMismatch = 0x1103;
constexpr Esp32SdkError kEsp32NvsNoSpace = 0x1105;
constexpr Esp32SdkError kEsp32NvsInvalidLength = 0x110c;

struct Esp32PartitionIdentity {
  uint32_t address = 0;
  uint32_t size = 0;
  uint8_t type = 0;
  uint8_t subtype = 0;
  char label[17] = {};
  bool encrypted = false;
  bool defaultFlash = false;
};

inline bool esp32PartitionEquals(const Esp32PartitionIdentity& a,
                                const Esp32PartitionIdentity& b) {
  return a.address == b.address && a.size == b.size && a.type == b.type &&
         a.subtype == b.subtype && memcmp(a.label, b.label, sizeof(a.label)) == 0 &&
         a.encrypted == b.encrypted && a.defaultFlash == b.defaultFlash;
}

enum class Esp32ImageState : uint32_t {
  New = 0, PendingVerify = 1, Valid = 2, Invalid = 3, Aborted = 4, Undefined = UINT32_MAX
};

struct Esp32PartitionSnapshot {
  static constexpr size_t kPartitionCount = 6;
  uint32_t flashSize = 0;
  uint32_t physicalFlashSize = 0;
  size_t count = 0;
  Esp32PartitionIdentity table[kPartitionCount] = {};
  Esp32PartitionIdentity running;
  Esp32PartitionIdentity boot;
  Esp32PartitionIdentity next;
  Esp32ImageState appStates[2] = {Esp32ImageState::Undefined, Esp32ImageState::Undefined};
};

class Esp32S3PartitionLayout {
public:
  static Esp32PartitionIdentity entry(size_t index) {
    static const char* const labels[] = {"nvs", "otadata", "app0", "app1", "spiffs", "coredump"};
    static const uint32_t addresses[] = {0x9000, 0xe000, 0x10000, 0x340000, 0x670000, 0x7f0000};
    static const uint32_t sizes[] = {0x5000, 0x2000, 0x330000, 0x330000, 0x180000, 0x10000};
    static const uint8_t types[] = {1, 1, 0, 0, 1, 1};
    static const uint8_t subtypes[] = {2, 0, 0x10, 0x11, 0x82, 3};
    Esp32PartitionIdentity out;
    if (index >= Esp32PartitionSnapshot::kPartitionCount) return out;
    out.address = addresses[index];
    out.size = sizes[index];
    out.type = types[index];
    out.subtype = subtypes[index];
    memcpy(out.label, labels[index], strlen(labels[index]) + 1);
    out.defaultFlash = true;
    return out;
  }

  // Table order is not significant; duplicates, extra entries and altered
  // flags/labels/offsets are. No partition table is written by this backend.
  static bool matches(const Esp32PartitionSnapshot& snapshot) {
    if (snapshot.flashSize != 0x800000 || snapshot.physicalFlashSize != 0x800000 ||
        snapshot.count != Esp32PartitionSnapshot::kPartitionCount)
      return false;
    for (size_t i = 0; i < Esp32PartitionSnapshot::kPartitionCount; ++i) {
      size_t matches = 0;
      for (size_t j = 0; j < snapshot.count; ++j)
        if (esp32PartitionEquals(entry(i), snapshot.table[j])) ++matches;
      if (matches != 1) return false;
    }
    return true;
  }
};

// The board integration must arbitrate ALL update paths (including web/USB
// updaters). IDF exposes no API for enumerating outstanding esp_ota_begin
// handles. Unknown ownership is a refusal, not an implicit lease.
enum class Esp32UpdateOwnership : uint8_t { Unknown, ExclusiveStorage, OtherUpdater };
class Esp32UpdateOwner {
public:
  virtual ~Esp32UpdateOwner() = default;
  virtual Esp32UpdateOwnership ownership(const Esp32PartitionIdentity& partition) const = 0;
};

class Esp32PartitionApi {
public:
  virtual ~Esp32PartitionApi() = default;
  virtual Esp32SdkError inspect(Esp32PartitionSnapshot& out) const = 0;
  virtual Esp32SdkError read(const Esp32PartitionIdentity& partition, uint32_t offset,
                            uint8_t* data, uint32_t len) const = 0;
  virtual Esp32SdkError write(const Esp32PartitionIdentity& partition, uint32_t offset,
                             const uint8_t* data, uint32_t len) = 0;
  virtual Esp32SdkError erase(const Esp32PartitionIdentity& partition, uint32_t offset,
                             uint32_t len) = 0;
};

#if defined(ESP32_PLATFORM)
class Esp32IdfPartitionApi final : public Esp32PartitionApi {
public:
  Esp32SdkError inspect(Esp32PartitionSnapshot& out) const override;
  Esp32SdkError read(const Esp32PartitionIdentity&, uint32_t, uint8_t*, uint32_t) const override;
  Esp32SdkError write(const Esp32PartitionIdentity&, uint32_t, const uint8_t*, uint32_t) override;
  Esp32SdkError erase(const Esp32PartitionIdentity&, uint32_t, uint32_t) override;
};
#endif

}  // namespace storage
}  // namespace ota
