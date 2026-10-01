#pragma once

// Cold-evidence classification shared by data cells and witness records.
// This is deliberately a richer taxonomy than the runtime-facing
// OtaSequenceBackingResult (see ota/runtime/OtaSequenceBackingPort.h): it
// describes what the STORAGE MEDIUM shows, not yet what a caller is
// authorized to conclude from it. OtaSecurityStore.h is responsible for
// combining evidence across a data cell AND its opposite-bank witness (and
// prior generations' snapshots) to decide the final, conservative
// runtime-facing result.
#include <stdint.h>

namespace ota {
namespace security {

enum class OtaSecurityEvidence : uint8_t {
  // Body bytes are complete, structurally valid (CRC matches) AND the
  // commit marker is the exact expected constant: a fully durable record.
  Committed = 0,

  // Body bytes are complete and CRC-valid, but the marker is ANY other
  // value -- including all-0xFF (never programmed). This is a POSSIBLE
  // commitment: the body write may have landed just before a crash that
  // pre-empted the marker write, or (for a witness) the data-side half of
  // a two-phase append may still be in flight. Must be preserved/burned,
  // never silently discarded in favor of an older head.
  BodyOnly = 1,

  // Every byte in the record (header + payload + crc + marker, or witness
  // record) reads back as 0xFF: this slot has never been programmed in
  // the current generation. Describes the STORAGE, not authority -- it is
  // never, by itself, proof of "never commissioned" (see
  // ITxSequenceCommissioningAuthority's doc comment in
  // OtaSequenceBackingPort.h for the identical principle applied to the
  // counter-port layer).
  AbsentBytes = 2,

  // Non-blank bytes that are neither a valid CRC-matching body nor a
  // conflicting-binding match: this is real, unrecoverable damage to this
  // one record. Also covers "CRC matched but the binding fields
  // (identity/generation/slot) don't match what was expected" -- that is
  // equally unprovable, never silently accepted as if it were the
  // expected record.
  Unprovable = 3,

  // The underlying FlashDevice/FlashRegion itself reported a non-Ok
  // status for a read -- distinct from a content-based classification;
  // callers must check flash status codes and never fold an IoError into
  // a success-shaped default.
  IoError = 4,
};

}  // namespace security
}  // namespace ota
