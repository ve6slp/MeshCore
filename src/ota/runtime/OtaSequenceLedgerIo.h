#pragma once

#include <stdint.h>
#include <string.h>

#include "ota/platform/FlashRegion.h"
#include "ota/storage/XiaoOtaTransactionalWriter.h"

namespace meshcore {
namespace ota {
namespace runtime {

// CommissionVirgin requires independent, durable proof that this identity
// has never used these keys. Missing records are not that proof.
enum class OtaSequenceInitialization : uint8_t {
  RequireExisting = 0,
  CommissionVirgin = 1,
};

template <typename Record>
class OtaSequenceLedgerIo {
public:
  static bool readNewest(const ::ota::platform::FlashRegion& region, uint32_t& out_value,
                         uint32_t* out_slot = nullptr) {
    if (!Record::regionIsValid(region)) return false;
    uint32_t newest = 0;
    uint32_t newest_slot = 0;
    for (uint32_t slot = 0; slot < 2; ++slot) {
      uint8_t bytes[Record::kRecordBytes];
      if (!::ota::platform::isOk(region.read(slot * region.eraseUnitBytes(), bytes, sizeof(bytes)))) {
        return false;
      }
      if (Record::isBlank(bytes, sizeof(bytes))) continue;
      // An older valid slot cannot prove a corrupt/unreadable newer slot
      // never issued a sequence or admitted an authenticated frame.
      if (!Record::isValidRecord(bytes, sizeof(bytes))) return false;
      const uint32_t value = Record::value(bytes);
      if (value == 0) return false;
      if (value >= newest) {
        newest = value;
        newest_slot = slot;
      }
    }
    out_value = newest;
    if (out_slot != nullptr) *out_slot = newest_slot;
    return true;
  }

  static bool advance(::ota::platform::FlashRegion& region, uint32_t new_value) {
    uint32_t current_value = 0;
    uint32_t current_slot = 0;
    if (!readNewest(region, current_value, &current_slot) || new_value == 0 || new_value <= current_value) {
      return false;
    }
    const uint32_t target_slot = current_value == 0 ? 0 : 1 - current_slot;
    uint8_t record[Record::kRecordBytes];
    if (Record::serialize(new_value, record, sizeof(record)) != sizeof(record)) return false;
    const uint32_t offset = target_slot * region.eraseUnitBytes();
    if (!::ota::storage::writeOtaJournalRecordTransactional(
            region, offset, record, sizeof(record), Record::kCommitMarkerOffset,
            sizeof(record) - Record::kCommitMarkerOffset)) {
      return false;
    }
    uint8_t readback[Record::kRecordBytes];
    return ::ota::platform::isOk(region.read(offset, readback, sizeof(readback))) &&
           memcmp(record, readback, sizeof(record)) == 0 && Record::isValidRecord(readback, sizeof(readback));
  }
};

} // namespace runtime
} // namespace ota
} // namespace meshcore
