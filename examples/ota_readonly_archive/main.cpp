// Read-only USB maintenance archival firmware for the authorized
// nRF52840/XIAO + SX1262 lab boards.
//
// SCOPE (bounded prerequisite for LoRa OTA hardware commissioning): this
// image exists ONLY so the two authorized lab boards' physical media can be
// losslessly archived, over USB, before any custom loader/store
// provisioning touches them. It is a SEPARATE, EXPLICIT, USB-ONLY
// maintenance profile -- MAIN adds the build environment and flashes it
// deliberately, after acceptance; it is never the ordinary companion
// firmware and is never flashed automatically by anything in this tree.
//
// What this firmware deliberately does NOT do:
//   - no InternalFS/ExtraFS begin/format/migrate, no identity generation;
//   - no radio transmit (no LoRa/RadioLib includes at all);
//   - no BLE/WiFi (no Bluefruit/WiFi includes at all);
//   - no QSPI/internal flash WRITE or ERASE endpoint of any kind --
//     ota::platform::Nrf52FlashAdapter::program()/eraseSector() are never
//     called anywhere in this file;
//   - no installer/grant/automatic reset;
//   - no restore endpoint and no destructive built-in test.
// QSPI initialization (flash.begin()) is allowed and required to be able to
// read the external part at all, but initializing it does not erase or
// program anything (see Nrf52FlashAdapter::begin(), which only issues a
// JEDEC-ID read to confirm the part responds).
//
// Every request/response is a bounded, fixed-size binary frame (see
// ReadonlyArchiveProtocol.h). There is no text protocol interleaved on the
// same serial connection -- mixing human-readable logs into a binary framed
// link makes framing ambiguous, so this firmware never calls
// Serial.print()/println() at all.

#include <Arduino.h>
#include <Adafruit_TinyUSB.h>

#include <ota/platform/Nrf52FlashAdapter.h>

#include "ReadonlyArchiveProtocol.h"

// Hard compile-time guards: this firmware must only ever be built as the
// dedicated USB-only maintenance profile against a real nRF52840. Failing
// closed here (rather than silently falling back to a zero UID, or letting
// this file get linked into some other profile that happens to also have
// BLE/WiFi enabled) avoids ever shipping a build that quietly reports a
// fake identity, or that carries this read-only-flash-dump capability
// behind a radio interface it was never bounded/reviewed for.
#if !defined(NRF52840_XXAA)
#error "examples/ota_readonly_archive requires NRF52840_XXAA (the real nRF52840 FICR register " \
       "set); refusing to build a silent zero-UID fallback image"
#endif
#if !defined(ENABLE_USB_INTERFACE)
#error "examples/ota_readonly_archive is a USB-only maintenance profile and requires ENABLE_USB_INTERFACE"
#endif
#if defined(BLE_PIN_CODE)
#error "examples/ota_readonly_archive must never be linked into a BLE-enabled build profile"
#endif
#if defined(WIFI_SSID) || defined(WIFI_PWD) || defined(WIFI_DEBUG_LOGGING)
#error "examples/ota_readonly_archive must never be linked into a WiFi-enabled build profile"
#endif

namespace {

using ota_readonly_archive::Opcode;
using ota_readonly_archive::Region;
using ota_readonly_archive::Request;
using ota_readonly_archive::Response;
using ota_readonly_archive::Status;

ota::platform::Nrf52FlashAdapter qspi_flash;
bool qspi_ready = false;

// Bytes-per-instruction FICR readout. On the real board this is exactly the
// same 64-bit value the Adafruit bootloader derives the board's USB serial
// number from (see its usb_desc.h get_serial_number(): the printed serial
// is "%08lX%08lX" of DEVICEID[1] then DEVICEID[0]); this firmware reports
// the two 32-bit words in that SAME big-endian byte order so a host can
// directly compare against the stable hex serial pinned in
// lab/devices.ini without any reinterpretation. This exact packing also
// matches this tree's own canonical convention for a device's full FICR
// unique id (see bootloader/xiao_nrf52840_ota/src/xiao_ota_boot.c's
// hw_device_address(): `((uint64_t)DEVICEID[1] << 32) | DEVICEID[0]`,
// serialized here most-significant-byte-first).
void readFicrUid(uint8_t out[8]) {
  // The top-of-file #error guard guarantees NRF52840_XXAA is always defined
  // whenever this translation unit compiles at all -- no zero-UID fallback
  // path exists or is reachable.
  const uint32_t hi = NRF_FICR->DEVICEID[1];
  const uint32_t lo = NRF_FICR->DEVICEID[0];
  out[0] = static_cast<uint8_t>(hi >> 24);
  out[1] = static_cast<uint8_t>(hi >> 16);
  out[2] = static_cast<uint8_t>(hi >> 8);
  out[3] = static_cast<uint8_t>(hi);
  out[4] = static_cast<uint8_t>(lo >> 24);
  out[5] = static_cast<uint8_t>(lo >> 16);
  out[6] = static_cast<uint8_t>(lo >> 8);
  out[7] = static_cast<uint8_t>(lo);
}

// Direct, read-only access to the nRF52840's memory-mapped internal flash.
// This is NOT Adafruit_LittleFS/InternalFS -- no filesystem is mounted, no
// NVMC write/erase register is ever touched, this is a bounded read exactly
// like reading any other const array. Bounds are enforced by the caller
// (dispatchRead()) against kInternalFlashRegionBytes before this is ever
// invoked.
//
// Deliberately NOT a memcpy() from `reinterpret_cast<const void*>(0)`: on
// this target, address 0 is a genuinely valid, dereferenceable location
// (the Cortex-M4 vector table itself lives there -- the same
// address-0-is-real-memory idiom this SDK's own boot code depends on), but
// a raw non-volatile pointer whose numeric value happens to be 0 can still
// be assumed unreachable/null by some compilers' UB-based optimizations. A
// `volatile`-qualified byte-at-a-time read cannot be elided or assumed
// unreachable by the optimizer regardless of the pointer's numeric value,
// which is the standard, defensive idiom for this exact situation.
void readInternalFlash(uint32_t offset, uint8_t* out, uint32_t len) {
  volatile const uint8_t* src = reinterpret_cast<volatile const uint8_t*>(static_cast<uintptr_t>(offset));
  for (uint32_t i = 0; i < len; ++i) {
    out[i] = src[i];
  }
}

// Fills in the OP_IDENTITY response payload. Returns the payload length
// actually used (always well under kMaxChunkBytes).
uint32_t buildIdentityPayload(uint8_t* payload) {
  uint32_t offset = 0;
  readFicrUid(payload + offset);
  offset += 8;
  payload[offset++] = ota_readonly_archive::kProtocolVersion;
  payload[offset++] = ota_readonly_archive::kDiagnosticProfileId;
  ota_readonly_archive::putU32(payload + offset, ota_readonly_archive::kInternalFlashRegionBytes);
  offset += 4;
  ota_readonly_archive::putU32(payload + offset, qspi_ready ? ota_readonly_archive::kQspiRegionBytes : 0u);
  offset += 4;
  payload[offset++] = qspi_ready ? 1 : 0;
  if (qspi_ready) {
    memcpy(payload + offset, qspi_flash.jedecId(), 3);
  } else {
    memset(payload + offset, 0, 3);
  }
  offset += 3;
  return offset;
}

bool rangeFits(uint32_t addr, uint32_t length, uint32_t region_bytes) {
  // Guards against addr+length wrapping past UINT32_MAX as well as against
  // it merely exceeding the region -- both are "out of range", neither is
  // ever silently truncated to something that "succeeds".
  if (length > region_bytes) return false;
  if (addr > region_bytes - length) return false;
  return true;
}

void dispatch(const Request& request, bool header_crc_ok, Response& response) {
  // Explicitly zero the whole payload up front (defense-in-depth on top of
  // Response::payload's own default member initializer): no code path
  // below is ever allowed to leave stale/uninitialized stack bytes in the
  // unused tail past `response.length` -- encodeResponse() also zero-pads
  // the wire frame independently, so this is never depended on twice, only
  // guaranteed twice.
  memset(response.payload, 0, sizeof(response.payload));
  response.request_id = request.request_id;
  response.opcode = request.opcode;
  response.region = request.region;
  response.addr = request.addr;
  response.length = 0;

  if (!header_crc_ok) {
    response.status = Status::BadHeaderCrc;
    return;
  }
  if (request.opcode != Opcode::Identity && request.opcode != Opcode::Read) {
    response.status = Status::BadOpcode;
    return;
  }

  if (request.opcode == Opcode::Identity) {
    if (request.region != Region::Internal || request.addr != 0 || request.length != 0) {
      // region is forced to Region::Internal(0) as the only defined enum
      // value that also satisfies "must be zero" for this opcode.
      response.status = Status::Malformed;
      return;
    }
    response.length = buildIdentityPayload(response.payload);
    response.status = Status::Ok;
    return;
  }

  // OP_READ.
  if (request.region != Region::Internal && request.region != Region::Qspi) {
    response.status = Status::BadRegion;
    return;
  }
  if (request.length == 0 || request.length > ota_readonly_archive::kMaxChunkBytes) {
    response.status = Status::Overflow;
    return;
  }
  const uint32_t region_bytes = request.region == Region::Internal
                                    ? ota_readonly_archive::kInternalFlashRegionBytes
                                    : ota_readonly_archive::kQspiRegionBytes;
  if (!rangeFits(request.addr, request.length, region_bytes)) {
    response.status = Status::OutOfRange;
    return;
  }

  if (request.region == Region::Internal) {
    readInternalFlash(request.addr, response.payload, request.length);
    response.length = request.length;
    response.status = Status::Ok;
    return;
  }

  // Region::Qspi.
  if (!qspi_ready) {
    response.status = Status::NotInitialized;
    return;
  }
  const ota::platform::FlashStatus flash_status =
      qspi_flash.read(request.addr, response.payload, request.length);
  if (!ota::platform::isOk(flash_status)) {
    response.status = Status::IoError;
    return;
  }
  response.length = request.length;
  response.status = Status::Ok;
}

// Fixed-size receive state machine: scan for magic, then collect exactly
// kRequestFrameBytes before dispatching. A partial frame that stalls past
// `kByteTimeoutMs` since its last byte is dropped and resynced from
// scratch -- never dispatched as-is, and no response is sent for a frame
// this firmware never finished receiving (it cannot even trust the
// request_id it would echo).
constexpr uint32_t kByteTimeoutMs = 2000;

uint8_t request_buffer[ota_readonly_archive::kRequestFrameBytes];
uint32_t request_filled = 0;
uint32_t last_byte_at_ms = 0;

void resetReceiveState() {
  request_filled = 0;
}

void handleByte(uint8_t value) {
  const uint32_t now = millis();
  if (request_filled > 0 && (now - last_byte_at_ms) > kByteTimeoutMs) {
    resetReceiveState();
  }
  last_byte_at_ms = now;

  if (request_filled < sizeof(ota_readonly_archive::kMagic)) {
    if (value == static_cast<uint8_t>(ota_readonly_archive::kMagic[request_filled])) {
      request_buffer[request_filled++] = value;
    } else if (value == static_cast<uint8_t>(ota_readonly_archive::kMagic[0])) {
      // Resync on a byte that could start a new magic sequence.
      request_filled = 1;
      request_buffer[0] = value;
    } else {
      resetReceiveState();
    }
    return;
  }

  request_buffer[request_filled++] = value;
  if (request_filled < sizeof(request_buffer)) {
    return;
  }

  // Full fixed-size request frame collected; decode, dispatch, respond.
  Request request;
  bool header_crc_ok = false;
  const bool magic_ok = ota_readonly_archive::decodeRequest(request_buffer, request, header_crc_ok);
  resetReceiveState();
  if (!magic_ok) {
    // Defensive only: handleByte() never lets a non-matching magic reach
    // here in the first place.
    return;
  }

  Response response;
  dispatch(request, header_crc_ok, response);

  uint8_t wire[ota_readonly_archive::kResponseFrameBytes];
  ota_readonly_archive::encodeResponse(wire, response);
  Serial.write(wire, sizeof(wire));
  Serial.flush();
}

}  // namespace

void setup() {
  Serial.begin(115200);
  const uint32_t started = millis();
  while (!Serial && millis() - started < 5000u) {
    delay(10);
  }

  // QSPI init is allowed (it only issues a JEDEC-ID read, see
  // Nrf52FlashAdapter::begin()) but its success/failure is never fatal to
  // bringing up this firmware: a device whose QSPI part fails to respond
  // can still serve OP_IDENTITY and internal-flash OP_READ, and the host
  // tool is required to treat a not-ready QSPI as an explicit refusal
  // rather than silently accepting an incomplete archive.
  qspi_ready = ota::platform::isOk(qspi_flash.begin());
}

void loop() {
  while (Serial.available() > 0) {
    handleByte(static_cast<uint8_t>(Serial.read()));
  }
}
