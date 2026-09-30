#pragma once

// Bounded, fixed-size, binary request/response framing for the read-only USB
// maintenance archival firmware (see main.cpp in this directory).
//
// THIS IS A SEPARATE, EXPLICIT, USB-ONLY MAINTENANCE PROFILE. It is not the
// ordinary companion firmware, it grants no OTA installer/commissioning/
// authority behaviour, and it is never flashed automatically -- MAIN wires an
// explicit build environment and flashes it only after acceptance, and only
// for the bounded purpose of archiving the two authorized lab boards before
// any custom loader/store provisioning touches them. It does not write,
// erase, format, or migrate ANYTHING; every opcode below is read-only.
//
// This header is the single source of truth for the wire format. The host
// tool (scripts/ota_lab_archive.py) is a separate, independent
// re-implementation of the exact same byte layout in Python (it cannot
// #include a C++ header) -- keep the two in lockstep; scripts/tests/
// test_ota_lab_archive.py cross-checks the frame sizes declared here against
// the ones the host computes from its own struct formats.
//
// Frame shapes are always fully fixed length so a host never has to parse a
// variable-length field to know how many more bytes to read -- every
// request is exactly kRequestFrameBytes, every response is exactly
// kResponseFrameBytes, always sent in full (payload zero-padded past the
// real length), even on error. There is no "short success" framing: a
// caller either gets a complete, CRC-verified frame or none at all.

#include <stdint.h>
#include <string.h>

#include "ota/storage/Crc32.h"

namespace ota_readonly_archive {

// 4-byte magic identifying this exact wire format/version. Bump to "ROA2"
// (and the mirrored Python constant) for any incompatible framing change;
// never silently reinterpret old bytes under a new layout.
inline constexpr char kMagic[4] = {'R', 'O', 'A', '1'};
inline constexpr uint8_t kProtocolVersion = 1;

// A profile id the host can use to confirm it is actually talking to THIS
// bounded read-only maintenance firmware and not some other USB image that
// happens to echo similarly-shaped bytes. Never reused for any other
// firmware profile.
inline constexpr uint8_t kDiagnosticProfileId = 0x01;

// Small working chunk only -- callers must never request more than this in
// one OP_READ, and this firmware never allocates a payload buffer larger
// than this on the stack.
inline constexpr uint32_t kMaxChunkBytes = 256;

// Bounded raw-read windows. Deliberately NOT derived from the QSPI OTA
// partition contract (src/ota/platform/Nrf52FlashLayoutContract.h) for the
// wire bound itself -- that header still governs the *named sub-region*
// metadata the host records (see scripts/ota_lab_archive.py), but the raw
// read opcode is bounded by physical device size, independent of how any
// current or future OTA scheme subdivides it.
inline constexpr uint32_t kInternalFlashRegionBytes = 0x100000u;  // nRF52840 internal flash, 1 MiB.
inline constexpr uint32_t kQspiRegionBytes = 0x200000u;           // P25Q16H external QSPI NOR, 2 MiB.

enum class Opcode : uint8_t {
  Identity = 1,  // Query board/FICR identity + profile. region/addr/length must all be 0.
  Read = 2,      // Bounded raw read of `length` bytes at `addr` within `region`.
};

enum class Region : uint8_t {
  Internal = 0,  // [0, kInternalFlashRegionBytes)
  Qspi = 1,      // [0, kQspiRegionBytes), requires QSPI init to have succeeded.
};

// Every explicit, distinguishable failure this firmware can report. There is
// deliberately no generic "error" catch-all: every rejection reason the task
// requires (invalid/overflow/out-of-range/malformed) has its own status so a
// host never has to guess why a request was refused.
enum class Status : uint8_t {
  Ok = 0,
  BadMagic = 1,           // Framing resync failure (should never reach parse; defensive).
  BadHeaderCrc = 2,        // Request header_crc32 did not match the received header bytes.
  BadOpcode = 3,           // Opcode is not one of the above.
  BadRegion = 4,           // Region is not one of the above (OP_READ only).
  OutOfRange = 5,          // addr/length falls outside the region's bound.
  Overflow = 6,            // length is 0, exceeds kMaxChunkBytes, or addr+length overflows.
  NotInitialized = 7,      // QSPI region requested but QSPI init never succeeded.
  IoError = 8,             // Underlying flash read failed.
  Malformed = 9,           // Reserved bytes nonzero, or addr/length nonzero for OP_IDENTITY.
};

// ---- Request frame: exactly kRequestFrameBytes, always. ----
// Offset  Size  Field
//   0      4    magic            "ROA1"
//   4      4    request_id       caller-chosen, echoed back unmodified
//   8      1    opcode           Opcode
//   9      1    region           Region (OP_READ only; must be 0 for OP_IDENTITY)
//  10      2    reserved         MUST be {0,0}; firmware rejects any other value
//  12      4    addr             region-relative offset (OP_READ only; must be 0 for OP_IDENTITY)
//  16      4    length           requested byte count (OP_READ only; must be 0 for OP_IDENTITY)
//  20      4    header_crc32     Crc32::computeFinalized() over bytes [0,20)
inline constexpr uint32_t kRequestFrameBytes = 24;

// ---- Response frame: exactly kResponseFrameBytes, always, every request. ----
// Offset  Size  Field
//   0      4    magic            "ROA1"
//   4      4    request_id       echoed from the request that produced this response
//   8      1    status           Status
//   9      1    opcode           echoed
//  10      1    region           echoed
//  11      1    reserved         always 0
//  12      4    addr             echoed
//  16      4    length           actual valid payload byte count (0 unless status==Ok)
//  20    256    payload          zero-padded past `length`; never meaningful past `length`
// 276      4    payload_crc32    Crc32::computeFinalized() over payload[0,length); 0 if length==0
// 280      4    frame_crc32      Crc32::computeFinalized() over bytes [0,280)
inline constexpr uint32_t kResponsePayloadOffset = 20;
inline constexpr uint32_t kResponseFrameBytes =
    kResponsePayloadOffset + kMaxChunkBytes + 4 /*payload_crc32*/ + 4 /*frame_crc32*/;

struct Request {
  uint32_t request_id = 0;
  Opcode opcode = Opcode::Identity;
  Region region = Region::Internal;
  uint32_t addr = 0;
  uint32_t length = 0;
};

struct Response {
  uint32_t request_id = 0;
  Status status = Status::Ok;
  Opcode opcode = Opcode::Identity;
  Region region = Region::Internal;
  uint32_t addr = 0;
  uint32_t length = 0;
  uint8_t payload[kMaxChunkBytes] = {0};
};

inline void putU32(uint8_t* out, uint32_t value) {
  out[0] = static_cast<uint8_t>(value);
  out[1] = static_cast<uint8_t>(value >> 8);
  out[2] = static_cast<uint8_t>(value >> 16);
  out[3] = static_cast<uint8_t>(value >> 24);
}

inline uint32_t getU32(const uint8_t* in) {
  return static_cast<uint32_t>(in[0]) | (static_cast<uint32_t>(in[1]) << 8) |
         (static_cast<uint32_t>(in[2]) << 16) | (static_cast<uint32_t>(in[3]) << 24);
}

// Parses exactly kRequestFrameBytes of already-received bytes (the caller is
// responsible for having resynced to `kMagic` first). Returns false only for
// a magic mismatch (defensive; callers should not reach here without having
// matched magic already) -- every OTHER problem (bad crc/opcode/region/
// bounds/reserved bytes) is left for the caller to detect via the returned
// `out` fields plus its own validation, so the exact same rejection logic is
// shared between decode and the one real caller (main.cpp's dispatch).
inline bool decodeRequest(const uint8_t* in, Request& out, bool& header_crc_ok) {
  if (memcmp(in, kMagic, sizeof(kMagic)) != 0) {
    return false;
  }
  out.request_id = getU32(in + 4);
  out.opcode = static_cast<Opcode>(in[8]);
  out.region = static_cast<Region>(in[9]);
  const bool reserved_zero = in[10] == 0 && in[11] == 0;
  out.addr = getU32(in + 12);
  out.length = getU32(in + 16);
  const uint32_t stored_crc = getU32(in + 20);
  const uint32_t computed_crc = ota::storage::Crc32::computeFinalized(in, 20);
  header_crc_ok = reserved_zero && (stored_crc == computed_crc);
  return true;
}

// Encodes a full fixed-size response frame, including both CRCs. `payload`
// may be nullptr only when length==0. Always writes exactly
// kResponseFrameBytes bytes to `out`, zero-padding the unused payload tail.
inline void encodeResponse(uint8_t* out, const Response& response) {
  memset(out, 0, kResponseFrameBytes);
  memcpy(out, kMagic, sizeof(kMagic));
  putU32(out + 4, response.request_id);
  out[8] = static_cast<uint8_t>(response.status);
  out[9] = static_cast<uint8_t>(response.opcode);
  out[10] = static_cast<uint8_t>(response.region);
  out[11] = 0;
  putU32(out + 12, response.addr);
  putU32(out + 16, response.length);
  if (response.length > 0) {
    memcpy(out + kResponsePayloadOffset, response.payload, response.length);
  }
  const uint32_t payload_crc =
      response.length > 0 ? ota::storage::Crc32::computeFinalized(out + kResponsePayloadOffset, response.length)
                          : 0u;
  putU32(out + kResponsePayloadOffset + kMaxChunkBytes, payload_crc);
  const uint32_t frame_crc =
      ota::storage::Crc32::computeFinalized(out, kResponsePayloadOffset + kMaxChunkBytes + 4);
  putU32(out + kResponsePayloadOffset + kMaxChunkBytes + 4, frame_crc);
}

}  // namespace ota_readonly_archive
