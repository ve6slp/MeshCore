#pragma once

// LoRa OTA first-production-commissioning USB control-channel ABI.
//
// Wire-format-only (no Authority/Store/Boot codec dependency, no Arduino
// dependency): this is the "shared FW ABI header" explicitly called for in
// the commissioning contract's section E -- a single source of truth for
// the opcode/header/object-kind byte layout, so the device-side USB router
// and the host-side Python codec can never independently drift on these
// constants. It carries typed objects (Measurement/B117/G-or-C238/P683/
// PrepareAuth267/ActivateAuth267/PrepareAck112/ActivateAck80/BootReceipt386/
// PrepareInput626) as OPAQUE sized byte blobs -- the actual field contents
// of those objects are Authority's/Store's/Boot's respective codecs
// (src/ota/authority/**, src/ota/security/**, bootloader/**), never
// reinterpreted here.
//
// This ABI is consumed by the maintenance session router; complete-frame
// admission is deliberately distinct from structural header parsing. The
// codecs do not implement USB lifetime, job execution, or authority.

#include "OtaByteStream.h"
#include "OtaWireTypes.h"

namespace meshcore {
namespace ota {
namespace protocol {

// Existing top-level USB/CLI command multiplexer byte this control channel
// is reserved under; existing values 0..5 (and the existing lab/text status
// codes 29/30) are unchanged -- this ABI only claims the previously-unused
// response code 31 and a new cmd=66 namespace, per the commissioning
// contract's explicit instruction not to reinterpret existing codes.
inline constexpr uint8_t kOtaControlCommand = 66;
inline constexpr uint8_t kOtaControlResponseCode = 31;
inline constexpr uint8_t kOtaControlAbiVersion = 1;

inline constexpr size_t kOtaControlSessionIdBytes = 16;
inline constexpr size_t kOtaControlChallengeBytes = 16;
inline constexpr size_t kOtaControlRequestHeaderSize = 37;
inline constexpr size_t kOtaControlReplyHeaderSize = 40;
inline constexpr size_t kOtaControlMaxDataLen = 128;
inline constexpr size_t kOtaControlMaxRequestWireSize = kOtaControlRequestHeaderSize + kOtaControlMaxDataLen;
// Largest single reply: 40-byte header + 128-byte data = 168 bytes, plus
// the existing 3-byte outer serial frame (one leading direction byte --
// '<' for host-to-device, '>' for device-to-host -- followed by LE16
// payload length; there is NO trailing delimiter byte) = 171, below the
// 176-byte transport ceiling this ABI must fit under.
inline constexpr size_t kOtaControlMaxReplyWireSize = kOtaControlReplyHeaderSize + kOtaControlMaxDataLen;

enum class OtaControlSubcommand : uint8_t {
  Open = 0x20,
  Measure = 0x21,
  PutFragment = 0x22,
  Certify = 0x23,
  Prepare = 0x24,
  Activate = 0x25,
  Poll = 0x26,
  ReadObject = 0x27,
  Cancel = 0x28,
  Challenge = 0x29,
  Close = 0x2A,
};

// Typed terminal/non-terminal outcomes a device-side job can report, per
// the commissioning contract's section G ("typed terminal refusals ...
// never false=>retry-forever or blank=>first-use"). RejectedChangedRequest
// rejects ONLY the single mismatched attempt -- it is NOT terminal for the
// underlying job: the original ticket/request's in-flight work must
// remain fully resumable (never cancelled, never silently overwritten,
// its single-use nonce/ownership never consumed) by a subsequent call
// that repeats the ORIGINAL arguments, or by Poll/ReadObject against the
// same ticket (those are read/offset operations, not mutations of the
// frozen original request). Only Ok/Pending/RejectedChangedRequest permit
// continued use of the same job ticket; every other status is terminal.
enum class OtaControlStatus : uint8_t {
  Ok = 0,
  Pending = 1,                // WouldBlock, same ticket + same request.
  RejectedChangedRequest = 2, // same ticket, changed arguments; original request/ticket remains resumable.
  Denied = 3,                 // foreign/stale ticket.
  Busy = 4,                   // new unticketed caller while occupied.
  Missing = 5,
  Corrupt = 6,
  Uncertain = 7, // side effects may have landed; not rolled back.
  OwnershipDenied = 8,
  NoCapacity = 9,
};

// Every value an objectKind byte may carry on the wire. Kind 0 (None) has
// no fixed size. Kinds 3/4/5 (Grant-or-Certificate/PrepareAuth/
// ActivateAuth) share a byte length with another distinct meaning per the
// contract text ("operation inside grant distinguishes them") -- the
// disambiguation lives in the opaque payload itself, not in this enum.
enum class OtaControlObjectKind : uint8_t {
  None = 0,
  Measurement = 1,
  BaselineManifestB117 = 2,
  GrantOrCertificate238 = 3,
  PrepareAuth267 = 4,
  ActivateAuth267 = 5,
  PreparedRootP683 = 6,
  PrepareAck112 = 7,
  ActivateAck80 = 8,
  BootReceipt386 = 9,
  PrepareInput626 = 10,
};

// Fixed byte size for a typed object kind (0 for None/unknown -- callers
// must not treat 0 as "unbounded"; None genuinely carries no payload).
inline size_t otaControlObjectKindFixedSize(OtaControlObjectKind kind) {
  switch (kind) {
  case OtaControlObjectKind::None:
    return 0;
  case OtaControlObjectKind::Measurement:
    return 235;
  case OtaControlObjectKind::BaselineManifestB117:
    return 117;
  case OtaControlObjectKind::GrantOrCertificate238:
    return 238;
  case OtaControlObjectKind::PrepareAuth267:
    return 267;
  case OtaControlObjectKind::ActivateAuth267:
    return 267;
  case OtaControlObjectKind::PreparedRootP683:
    return 683;
  case OtaControlObjectKind::PrepareAck112:
    return 112;
  case OtaControlObjectKind::ActivateAck80:
    return 80;
  case OtaControlObjectKind::BootReceipt386:
    return 386;
  case OtaControlObjectKind::PrepareInput626:
    return 626;
  }
  return 0;
}

// Typed codec failures are distinct from OtaControlStatus (runtime outcomes).
enum class OtaControlCodecResult : uint8_t {
  Ok,
  InvalidArgument,
  TruncatedFrame,
  ExtraFrameBytes,
  DataTooLarge,
  DataLengthMismatch,
  InvalidCommand,
  UnsupportedVersion,
  UnsupportedSubcommand,
  UnsupportedStatus,
  UnsupportedObjectKind,
  InvalidRequestId,
  InvalidSession,
  InvalidOpenShape,
  InvalidOperationShape,
  InvalidObjectLength,
  RangeOverflow,
  RangeOutOfBounds,
  InvalidMeasurementVersion,
  InvalidMeasurementRole,
  InvalidBootConfigId,
};

// Stable reason identifiers already emitted by OtaControlSessionRouter and
// the fail-closed backend. Additional backend-specific uint16 reason values
// remain opaque to this wire codec.
enum class OtaControlReason : uint16_t {
  None = 0,
  NoBackendBound = 1,
  UnknownSubcommand = 100,
  NoSession = 101,
  SessionMismatch = 102,
  Occupied = 103,
  ZeroTicket = 104,
  ForeignTicket = 105,
  BadObjectKind = 106,
  Overflow = 107,
};

// --------------------------- Request header (37B) ----------------------
// cmd:u8, sub:u8, version:u8, session:16B, requestId:BE32, jobTicket:BE32,
// objectKind:u8, total:BE32, offset:BE32, dataLen:u8.
struct OtaControlRequestHeader {
  uint8_t cmd = kOtaControlCommand;
  OtaControlSubcommand sub = OtaControlSubcommand::Open;
  uint8_t version = kOtaControlAbiVersion;
  uint8_t session[kOtaControlSessionIdBytes] = { 0 };
  uint32_t requestId = 0;
  uint32_t jobTicket = 0;
  OtaControlObjectKind objectKind = OtaControlObjectKind::None;
  uint32_t total = 0;
  uint32_t offset = 0;
  uint8_t dataLen = 0;
};

inline bool encodeOtaControlRequestHeader(const OtaControlRequestHeader &h, uint8_t *buf, size_t capacity) {
  if (buf == nullptr) return false;
  OtaBoundedWriter w(buf, capacity);
  bool ok = w.putU8(h.cmd) && w.putU8(static_cast<uint8_t>(h.sub)) && w.putU8(h.version) &&
            w.putBytes(h.session, kOtaControlSessionIdBytes) && w.putU32(h.requestId) &&
            w.putU32(h.jobTicket) && w.putU8(static_cast<uint8_t>(h.objectKind)) && w.putU32(h.total) &&
            w.putU32(h.offset) && w.putU8(h.dataLen);
  return ok && w.size() == kOtaControlRequestHeaderSize;
}

inline bool decodeOtaControlRequestHeader(const uint8_t *buf, size_t len, OtaControlRequestHeader &out) {
  if (buf == nullptr || len < kOtaControlRequestHeaderSize) return false;
  OtaControlRequestHeader decoded;
  OtaBoundedReader r(buf, kOtaControlRequestHeaderSize);
  uint8_t sub_raw = 0, kind_raw = 0;
  const bool ok = r.getU8(decoded.cmd) && r.getU8(sub_raw) && r.getU8(decoded.version) &&
                  r.getBytes(decoded.session, kOtaControlSessionIdBytes) && r.getU32(decoded.requestId) &&
                  r.getU32(decoded.jobTicket) && r.getU8(kind_raw) && r.getU32(decoded.total) &&
                  r.getU32(decoded.offset) && r.getU8(decoded.dataLen);
  if (!ok) return false;
  decoded.sub = static_cast<OtaControlSubcommand>(sub_raw);
  decoded.objectKind = static_cast<OtaControlObjectKind>(kind_raw);
  out = decoded;
  return true;
}

// --------------------------- Reply header (40B) -------------------------
// response:u8, sub:u8, version:u8, status:u8, reason:BE16, session:16B,
// requestId:BE32, jobTicket:BE32, objectKind:u8, total:BE32, offset:BE32,
// dataLen:u8.
struct OtaControlReplyHeader {
  uint8_t response = kOtaControlResponseCode;
  OtaControlSubcommand sub = OtaControlSubcommand::Open;
  uint8_t version = kOtaControlAbiVersion;
  OtaControlStatus status = OtaControlStatus::Ok;
  uint16_t reason = 0;
  uint8_t session[kOtaControlSessionIdBytes] = { 0 };
  uint32_t requestId = 0;
  uint32_t jobTicket = 0;
  OtaControlObjectKind objectKind = OtaControlObjectKind::None;
  uint32_t total = 0;
  uint32_t offset = 0;
  uint8_t dataLen = 0;
};

inline bool encodeOtaControlReplyHeader(const OtaControlReplyHeader &h, uint8_t *buf, size_t capacity) {
  if (buf == nullptr) return false;
  OtaBoundedWriter w(buf, capacity);
  bool ok = w.putU8(h.response) && w.putU8(static_cast<uint8_t>(h.sub)) && w.putU8(h.version) &&
            w.putU8(static_cast<uint8_t>(h.status)) && w.putU16(h.reason) &&
            w.putBytes(h.session, kOtaControlSessionIdBytes) && w.putU32(h.requestId) &&
            w.putU32(h.jobTicket) && w.putU8(static_cast<uint8_t>(h.objectKind)) && w.putU32(h.total) &&
            w.putU32(h.offset) && w.putU8(h.dataLen);
  return ok && w.size() == kOtaControlReplyHeaderSize;
}

inline bool decodeOtaControlReplyHeader(const uint8_t *buf, size_t len, OtaControlReplyHeader &out) {
  if (buf == nullptr || len < kOtaControlReplyHeaderSize) return false;
  OtaControlReplyHeader decoded;
  OtaBoundedReader r(buf, kOtaControlReplyHeaderSize);
  uint8_t sub_raw = 0, status_raw = 0, kind_raw = 0;
  const bool ok = r.getU8(decoded.response) && r.getU8(sub_raw) && r.getU8(decoded.version) &&
                  r.getU8(status_raw) && r.getU16(decoded.reason) &&
                  r.getBytes(decoded.session, kOtaControlSessionIdBytes) && r.getU32(decoded.requestId) &&
                  r.getU32(decoded.jobTicket) && r.getU8(kind_raw) && r.getU32(decoded.total) &&
                  r.getU32(decoded.offset) && r.getU8(decoded.dataLen);
  if (!ok) return false;
  decoded.sub = static_cast<OtaControlSubcommand>(sub_raw);
  decoded.status = static_cast<OtaControlStatus>(status_raw);
  decoded.objectKind = static_cast<OtaControlObjectKind>(kind_raw);
  out = decoded;
  return true;
}

struct OtaControlRequestFrameView {
  OtaControlRequestHeader header;
  const uint8_t *data = nullptr; // Points into the caller's frame; never owned.
  size_t payloadLen = 0;
};

struct OtaControlMeasurement {
  uint8_t version = 1;
  uint8_t uid8[8] = { 0 };
  uint8_t fullPublicKey[32] = { 0 };
  uint32_t profile = 0;
  uint32_t target = 0;
  uint32_t currentRole = 0;
  uint32_t layout = 0;
  uint8_t sdk28Sha256[32] = { 0 };
  uint32_t imageExtent = 0;
  uint32_t imageAddress = 0;
  uint8_t imageSha256[32] = { 0 };
  uint16_t imageCrc16 = 0;
  uint32_t loaderStart = 0;
  uint32_t loaderLength = 0;
  uint8_t loaderSha256[32] = { 0 };
  uint32_t bootConfigId = 0;
  uint8_t hostChallenge[16] = { 0 };
  uint8_t deviceNonce[16] = { 0 };
  uint8_t rawSdk28[28] = { 0 }; // Opaque original settings bytes, not host-endian words.
};

inline bool otaControlIsKnownSubcommand(uint8_t value) {
  return value >= static_cast<uint8_t>(OtaControlSubcommand::Open) &&
         value <= static_cast<uint8_t>(OtaControlSubcommand::Close);
}

inline bool otaControlIsKnownStatus(uint8_t value) {
  return value <= static_cast<uint8_t>(OtaControlStatus::NoCapacity);
}

namespace commissioning_detail {
inline bool isZero(const uint8_t *data, size_t size) {
  uint8_t aggregate = 0;
  for (size_t i = 0; i < size; ++i)
    aggregate |= data[i];
  return aggregate == 0;
}
inline OtaControlCodecResult validateRange(uint32_t total, uint32_t offset, uint32_t length) {
  if (length > UINT32_MAX - offset) return OtaControlCodecResult::RangeOverflow;
  if (offset + length > total) return OtaControlCodecResult::RangeOutOfBounds;
  return OtaControlCodecResult::Ok;
}
inline OtaControlCodecResult validateRequest(const OtaControlRequestHeader &h, size_t payloadLen) {
  if (h.cmd != kOtaControlCommand) return OtaControlCodecResult::InvalidCommand;
  if (h.version != kOtaControlAbiVersion) return OtaControlCodecResult::UnsupportedVersion;
  if (!otaControlIsKnownSubcommand(static_cast<uint8_t>(h.sub)))
    return OtaControlCodecResult::UnsupportedSubcommand;
  const size_t fixed = otaControlObjectKindFixedSize(h.objectKind);
  if (static_cast<uint8_t>(h.objectKind) > static_cast<uint8_t>(OtaControlObjectKind::PrepareInput626))
    return OtaControlCodecResult::UnsupportedObjectKind;
  if (h.dataLen > kOtaControlMaxDataLen || payloadLen > kOtaControlMaxDataLen)
    return OtaControlCodecResult::DataTooLarge;
  if (h.requestId == 0) return OtaControlCodecResult::InvalidRequestId;

  if (h.sub == OtaControlSubcommand::Open) {
    // OPEN carries NO payload: no host challenge, no purpose byte -- just
    // the all-zero session/ticket identity header. The device mints and
    // returns the fresh session id in the reply; there is no challenge yet.
    if (payloadLen != h.dataLen) return OtaControlCodecResult::DataLengthMismatch;
    if (!isZero(h.session, sizeof(h.session)) || h.jobTicket != 0)
      return OtaControlCodecResult::InvalidSession;
    if (h.objectKind != OtaControlObjectKind::None || h.total != 0 || h.offset != 0 || h.dataLen != 0 ||
        payloadLen != 0)
      return OtaControlCodecResult::InvalidOpenShape;
    return OtaControlCodecResult::Ok;
  }
  if (isZero(h.session, sizeof(h.session))) return OtaControlCodecResult::InvalidSession;

  if (h.sub == OtaControlSubcommand::Challenge) {
    // CHALLENGE is an inline CONTROL payload, not a transferred object:
    // Kind=None, total=dataLen=1, offset=0. The single payload byte is the
    // target purpose subcommand value (Prepare=0x24 or Activate=0x25);
    // this header-level check validates shape only -- the actual byte
    // VALUE is a semantic-admission concern the router checks once it has
    // the payload bytes (see OtaControlSessionRouter::handleChallenge()).
    if (h.objectKind != OtaControlObjectKind::None || h.total != 1 || h.offset != 0 || h.dataLen != 1 ||
        payloadLen != 1)
      return OtaControlCodecResult::InvalidOperationShape;
    return OtaControlCodecResult::Ok;
  }

  if (h.sub == OtaControlSubcommand::ReadObject) {
    if (payloadLen != 0) return OtaControlCodecResult::DataLengthMismatch;
    if (h.objectKind == OtaControlObjectKind::None || fixed == 0 || h.total != fixed || h.dataLen == 0)
      return OtaControlCodecResult::InvalidOperationShape;
    return validateRange(h.total, h.offset, h.dataLen);
  }
  if (h.sub == OtaControlSubcommand::PutFragment) {
    if (payloadLen != h.dataLen) return OtaControlCodecResult::DataLengthMismatch;
    if (h.objectKind == OtaControlObjectKind::None || fixed == 0 || h.total != fixed || h.dataLen == 0)
      return OtaControlCodecResult::InvalidOperationShape;
    return validateRange(h.total, h.offset, h.dataLen);
  }
  if (h.sub == OtaControlSubcommand::Cancel || h.sub == OtaControlSubcommand::Close ||
      h.sub == OtaControlSubcommand::Poll) {
    // These never reference an object or carry inline input -- strictly
    // header-only.
    if (payloadLen != 0 || h.dataLen != 0 || h.objectKind != OtaControlObjectKind::None || h.total != 0 ||
        h.offset != 0)
      return OtaControlCodecResult::InvalidOperationShape;
    return OtaControlCodecResult::Ok;
  }

  // Measure/Certify/Prepare/Activate: a job request may (a) be header-only
  // (continuing/re-polling an already-begun job), (b) reference a
  // PUT_FRAGMENT-uploaded object by kind (offset/dataLen are 0 here --
  // the full object is read from scratch, not re-transferred), or (c)
  // carry small inline input data directly (objectKind=None, dataLen>0).
  // Exactly one of these three shapes, never a mix.
  if (h.objectKind == OtaControlObjectKind::None) {
    if (h.total != 0 || h.offset != 0 || h.dataLen != payloadLen)
      return OtaControlCodecResult::InvalidOperationShape;
    return OtaControlCodecResult::Ok;
  }
  if (fixed == 0) return OtaControlCodecResult::UnsupportedObjectKind;
  if (h.total != fixed || h.offset != 0 || h.dataLen != 0 || payloadLen != 0)
    return OtaControlCodecResult::InvalidOperationShape;
  return OtaControlCodecResult::Ok;
}
inline OtaControlCodecResult validateMeasurement(const OtaControlMeasurement &m) {
  if (m.version != kOtaControlAbiVersion) return OtaControlCodecResult::InvalidMeasurementVersion;
  if (m.currentRole > 1) return OtaControlCodecResult::InvalidMeasurementRole;
  if (m.bootConfigId != 0x00010001u && m.bootConfigId != 0x00010002u)
    return OtaControlCodecResult::InvalidBootConfigId;
  return OtaControlCodecResult::Ok;
}
} // namespace commissioning_detail

// Semantic admission for CHALLENGE's single inline purpose byte -- the
// codec-level shape check above only validates length/offset/kind; the
// actual byte VALUE must be exactly the target operation's subcommand
// value (Prepare or Activate), checked by the caller once it has the
// payload bytes (router/semantic layer, not raw header decoding). Public
// (not commissioning_detail) because the session router calls this.
inline bool otaControlIsValidChallengePurposeByte(uint8_t purposeByte) {
  return purposeByte == static_cast<uint8_t>(OtaControlSubcommand::Prepare) ||
         purposeByte == static_cast<uint8_t>(OtaControlSubcommand::Activate);
}

// Public entry point for the full per-operation shape/range validation
// (section G: "raw header decoding is NOT semantic admission"). Routers
// MUST call this on every structurally-decoded request before touching
// any session/job state -- the legacy OtaControlRequestHeader parser only
// checks field widths/ranges, never operation-specific shape (e.g. that
// OPEN/CHALLENGE carry no transferred object, that PUT_FRAGMENT/
// READ_OBJECT's offset+dataLen stay within an object kind's fixed size,
// or that an unrecognised object kind -- whose fixed size is 0 -- is
// rejected rather than silently treated as Kind=None).
inline OtaControlCodecResult validateOtaControlRequestShape(const OtaControlRequestHeader &h,
                                                            size_t payloadLen) {
  return commissioning_detail::validateRequest(h, payloadLen);
}

// Disjoint reason-value range a router reports when it denies a request
// purely because validateOtaControlRequestShape() failed, so these never
// collide with OtaControlReason's own 0..107 values: reason =
// kOtaControlShapeReasonBase + the OtaControlCodecResult ordinal.
inline constexpr uint16_t kOtaControlShapeReasonBase = 200;

inline OtaControlCodecResult encodeOtaControlRequestFrame(const OtaControlRequestHeader &header,
                                                          const uint8_t *payload, size_t payloadLen,
                                                          uint8_t *output, size_t capacity,
                                                          size_t &outputLen) {
  const auto valid = commissioning_detail::validateRequest(header, payloadLen);
  if (valid != OtaControlCodecResult::Ok) return valid;
  if (payloadLen != 0 && payload == nullptr) return OtaControlCodecResult::InvalidArgument;
  if (output == nullptr) return OtaControlCodecResult::InvalidArgument;
  const size_t frameLen = kOtaControlRequestHeaderSize + payloadLen;
  if (capacity < frameLen) return OtaControlCodecResult::TruncatedFrame;
  uint8_t encoded[kOtaControlMaxRequestWireSize];
  if (!encodeOtaControlRequestHeader(header, encoded, kOtaControlRequestHeaderSize))
    return OtaControlCodecResult::InvalidArgument;
  for (size_t i = 0; i < payloadLen; ++i)
    encoded[kOtaControlRequestHeaderSize + i] = payload[i];
  for (size_t i = 0; i < frameLen; ++i)
    output[i] = encoded[i];
  outputLen = frameLen;
  return OtaControlCodecResult::Ok;
}

// Strict complete-request admission for routers. Unlike the legacy structural
// header parser above, this requires the exact complete payload length and
// validates all operation-specific shape/bounds rules. READ_OBJECT requests
// have no bytes after the header; dataLen is the requested read count.
inline OtaControlCodecResult decodeOtaControlRequestFrame(const uint8_t *frame, size_t frameLen,
                                                          OtaControlRequestFrameView &out) {
  if (frame == nullptr) return OtaControlCodecResult::InvalidArgument;
  if (frameLen < kOtaControlRequestHeaderSize) return OtaControlCodecResult::TruncatedFrame;
  if (frameLen > kOtaControlRequestHeaderSize + kOtaControlMaxDataLen)
    return OtaControlCodecResult::DataTooLarge;
  OtaControlRequestHeader header;
  if (!decodeOtaControlRequestHeader(frame, kOtaControlRequestHeaderSize, header))
    return OtaControlCodecResult::TruncatedFrame;
  const size_t payloadLen = frameLen - kOtaControlRequestHeaderSize;
  const OtaControlCodecResult result = commissioning_detail::validateRequest(header, payloadLen);
  if (result != OtaControlCodecResult::Ok) return result;
  OtaControlRequestFrameView decoded;
  decoded.header = header;
  decoded.payloadLen = payloadLen;
  decoded.data = payloadLen == 0 ? nullptr : frame + kOtaControlRequestHeaderSize;
  out = decoded;
  return OtaControlCodecResult::Ok;
}

// Strict reply validation (including Challenge's fixed 16-byte data response).
// The legacy header parser remains structural and intentionally accepts extra
// payload bytes; callers needing admission must use this complete-frame API.
inline OtaControlCodecResult validateOtaControlReplyFrame(const uint8_t *frame, size_t frameLen,
                                                          OtaControlReplyHeader &out) {
  if (frame == nullptr) return OtaControlCodecResult::InvalidArgument;
  if (frameLen < kOtaControlReplyHeaderSize) return OtaControlCodecResult::TruncatedFrame;
  if (frameLen > kOtaControlMaxReplyWireSize) return OtaControlCodecResult::DataTooLarge;
  OtaControlReplyHeader header;
  if (!decodeOtaControlReplyHeader(frame, kOtaControlReplyHeaderSize, header))
    return OtaControlCodecResult::TruncatedFrame;
  const size_t payloadLen = frameLen - kOtaControlReplyHeaderSize;
  if (header.response != kOtaControlResponseCode) return OtaControlCodecResult::InvalidCommand;
  if (header.version != kOtaControlAbiVersion) return OtaControlCodecResult::UnsupportedVersion;
  if (!otaControlIsKnownSubcommand(static_cast<uint8_t>(header.sub)))
    return OtaControlCodecResult::UnsupportedSubcommand;
  if (!otaControlIsKnownStatus(static_cast<uint8_t>(header.status)))
    return OtaControlCodecResult::UnsupportedStatus;
  if (header.requestId == 0) return OtaControlCodecResult::InvalidRequestId;
  if (header.dataLen > kOtaControlMaxDataLen || payloadLen > kOtaControlMaxDataLen)
    return OtaControlCodecResult::DataTooLarge;
  if (payloadLen != header.dataLen) return OtaControlCodecResult::DataLengthMismatch;
  if (static_cast<uint8_t>(header.objectKind) > static_cast<uint8_t>(OtaControlObjectKind::PrepareInput626))
    return OtaControlCodecResult::UnsupportedObjectKind;
  const size_t fixed = otaControlObjectKindFixedSize(header.objectKind);
  if (header.sub == OtaControlSubcommand::Challenge && header.status == OtaControlStatus::Ok) {
    if (payloadLen != kOtaControlChallengeBytes) return OtaControlCodecResult::DataLengthMismatch;
    if (header.objectKind != OtaControlObjectKind::None || header.total != 0 || header.offset != 0)
      return OtaControlCodecResult::InvalidOperationShape;
  } else if (header.sub == OtaControlSubcommand::ReadObject && header.status == OtaControlStatus::Ok) {
    if (header.objectKind == OtaControlObjectKind::None || fixed == 0 || header.total != fixed ||
        payloadLen == 0)
      return OtaControlCodecResult::InvalidObjectLength;
    const auto range = commissioning_detail::validateRange(header.total, header.offset, header.dataLen);
    if (range != OtaControlCodecResult::Ok) return range;
  } else if (payloadLen == 0) {
    if (header.sub == OtaControlSubcommand::PutFragment && header.objectKind != OtaControlObjectKind::None &&
        header.total == fixed) {
      const auto range = commissioning_detail::validateRange(header.total, header.offset, 0);
      if (range != OtaControlCodecResult::Ok) return range;
    } else if (header.total != 0 || header.offset != 0) {
      return OtaControlCodecResult::InvalidOperationShape;
    }
  } else {
    return OtaControlCodecResult::InvalidOperationShape;
  }
  out = header;
  return OtaControlCodecResult::Ok;
}

inline OtaControlCodecResult encodeOtaControlReplyFrame(const OtaControlReplyHeader &header,
                                                        const uint8_t *payload, size_t payloadLen,
                                                        uint8_t *output, size_t capacity, size_t &outputLen) {
  if (payloadLen > kOtaControlMaxDataLen) return OtaControlCodecResult::DataTooLarge;
  if (payloadLen != 0 && payload == nullptr) return OtaControlCodecResult::InvalidArgument;
  if (output == nullptr) return OtaControlCodecResult::InvalidArgument;
  const size_t frameLen = kOtaControlReplyHeaderSize + payloadLen;
  if (capacity < frameLen) return OtaControlCodecResult::TruncatedFrame;
  uint8_t encoded[kOtaControlMaxReplyWireSize];
  if (!encodeOtaControlReplyHeader(header, encoded, kOtaControlReplyHeaderSize))
    return OtaControlCodecResult::InvalidArgument;
  for (size_t i = 0; i < payloadLen; ++i)
    encoded[kOtaControlReplyHeaderSize + i] = payload[i];
  OtaControlReplyHeader checked;
  const auto valid = validateOtaControlReplyFrame(encoded, frameLen, checked);
  if (valid != OtaControlCodecResult::Ok) return valid;
  for (size_t i = 0; i < frameLen; ++i)
    output[i] = encoded[i];
  outputLen = frameLen;
  return OtaControlCodecResult::Ok;
}

inline OtaControlCodecResult encodeOtaControlMeasurement(const OtaControlMeasurement &m, uint8_t *output,
                                                         size_t capacity, size_t &outputLen) {
  const auto valid = commissioning_detail::validateMeasurement(m);
  if (valid != OtaControlCodecResult::Ok) return valid;
  if (output == nullptr) return OtaControlCodecResult::InvalidArgument;
  constexpr size_t kMeasurementBytes = 235;
  if (capacity < kMeasurementBytes) return OtaControlCodecResult::TruncatedFrame;
  uint8_t encoded[kMeasurementBytes];
  size_t pos = 0;
  encoded[pos++] = m.version;
  for (uint8_t value : m.uid8)
    encoded[pos++] = value;
  for (uint8_t value : m.fullPublicKey)
    encoded[pos++] = value;
  OtaBoundedWriter w(encoded + pos, sizeof(encoded) - pos);
  bool ok = w.putU32(m.profile) && w.putU32(m.target) && w.putU32(m.currentRole) && w.putU32(m.layout);
  pos += w.size();
  if (!ok) return OtaControlCodecResult::InvalidArgument;
  for (uint8_t value : m.sdk28Sha256)
    encoded[pos++] = value;
  OtaBoundedWriter tail(encoded + pos, sizeof(encoded) - pos);
  ok = tail.putU32(m.imageExtent) && tail.putU32(m.imageAddress);
  pos += tail.size();
  if (!ok) return OtaControlCodecResult::InvalidArgument;
  for (uint8_t value : m.imageSha256)
    encoded[pos++] = value;
  OtaBoundedWriter body(encoded + pos, sizeof(encoded) - pos);
  ok = body.putU16(m.imageCrc16) && body.putU32(m.loaderStart) && body.putU32(m.loaderLength);
  pos += body.size();
  if (!ok) return OtaControlCodecResult::InvalidArgument;
  for (uint8_t value : m.loaderSha256)
    encoded[pos++] = value;
  OtaBoundedWriter rest(encoded + pos, sizeof(encoded) - pos);
  ok = rest.putU32(m.bootConfigId) && rest.putBytes(m.hostChallenge, sizeof(m.hostChallenge)) &&
       rest.putBytes(m.deviceNonce, sizeof(m.deviceNonce)) && rest.putBytes(m.rawSdk28, sizeof(m.rawSdk28));
  pos += rest.size();
  if (!ok || pos != sizeof(encoded)) return OtaControlCodecResult::InvalidArgument;
  for (size_t i = 0; i < pos; ++i)
    output[i] = encoded[i];
  outputLen = pos;
  return OtaControlCodecResult::Ok;
}

inline OtaControlCodecResult decodeOtaControlMeasurement(const uint8_t *frame, size_t frameLen,
                                                         OtaControlMeasurement &out) {
  constexpr size_t kMeasurementBytes = 235;
  if (frame == nullptr) return OtaControlCodecResult::InvalidArgument;
  if (frameLen < kMeasurementBytes) return OtaControlCodecResult::TruncatedFrame;
  if (frameLen > kMeasurementBytes) return OtaControlCodecResult::ExtraFrameBytes;
  OtaControlMeasurement decoded;
  size_t pos = 0;
  decoded.version = frame[pos++];
  for (auto &value : decoded.uid8)
    value = frame[pos++];
  for (auto &value : decoded.fullPublicKey)
    value = frame[pos++];
  OtaBoundedReader r(frame + pos, frameLen - pos);
  bool ok = r.getU32(decoded.profile) && r.getU32(decoded.target) && r.getU32(decoded.currentRole) &&
            r.getU32(decoded.layout);
  pos += r.position();
  if (!ok) return OtaControlCodecResult::TruncatedFrame;
  for (auto &value : decoded.sdk28Sha256)
    value = frame[pos++];
  OtaBoundedReader tail(frame + pos, frameLen - pos);
  ok = tail.getU32(decoded.imageExtent) && tail.getU32(decoded.imageAddress);
  pos += tail.position();
  if (!ok) return OtaControlCodecResult::TruncatedFrame;
  for (auto &value : decoded.imageSha256)
    value = frame[pos++];
  OtaBoundedReader body(frame + pos, frameLen - pos);
  ok = body.getU16(decoded.imageCrc16) && body.getU32(decoded.loaderStart) &&
       body.getU32(decoded.loaderLength);
  pos += body.position();
  if (!ok) return OtaControlCodecResult::TruncatedFrame;
  for (auto &value : decoded.loaderSha256)
    value = frame[pos++];
  OtaBoundedReader rest(frame + pos, frameLen - pos);
  ok = rest.getU32(decoded.bootConfigId) &&
       rest.getBytes(decoded.hostChallenge, sizeof(decoded.hostChallenge)) &&
       rest.getBytes(decoded.deviceNonce, sizeof(decoded.deviceNonce)) &&
       rest.getBytes(decoded.rawSdk28, sizeof(decoded.rawSdk28));
  pos += rest.position();
  if (!ok || pos != frameLen) return OtaControlCodecResult::TruncatedFrame;
  const auto valid = commissioning_detail::validateMeasurement(decoded);
  if (valid != OtaControlCodecResult::Ok) return valid;
  out = decoded;
  return OtaControlCodecResult::Ok;
}

} // namespace protocol
} // namespace ota
} // namespace meshcore
