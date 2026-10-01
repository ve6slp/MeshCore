"""Bounded codec for MeshCore maintenance-channel payloads (not serial frames).

The existing outer serial length remains little-endian; internal ABI integers
are big-endian.

Parsing proves only that bytes have the assigned shape; it grants no authority,
permissions, entropy, job progress, idempotency, or completion. READ_OBJECT puts
the requested byte count in header.data_len and carries no request payload.
"""

from dataclasses import dataclass, field
from enum import IntEnum
import struct

COMMAND = 66
RESPONSE = 31
VERSION = 1
REQUEST_HEADER_SIZE = 37
REPLY_HEADER_SIZE = 40
MAX_DATA = 128
MAX_REQUEST = REQUEST_HEADER_SIZE + MAX_DATA
MAX_REPLY = REPLY_HEADER_SIZE + MAX_DATA
MEASUREMENT_SIZE = 235


class Subcommand(IntEnum):
    OPEN = 0x20
    MEASURE = 0x21
    PUT_FRAGMENT = 0x22
    CERTIFY = 0x23
    PREPARE = 0x24
    ACTIVATE = 0x25
    POLL = 0x26
    READ_OBJECT = 0x27
    CANCEL = 0x28
    CHALLENGE = 0x29
    CLOSE = 0x2A


class ObjectKind(IntEnum):
    NONE = 0
    MEASUREMENT = 1
    BASELINE_MANIFEST = 2
    AUTHORITY_GRANT = 3
    PREPARE_AUTHORIZATION = 4
    ACTIVATION_AUTHORIZATION = 5
    PREPARED_ARTIFACT = 6
    PREPARE_ACK = 7
    ACTIVATE_ACK = 8
    BOOT_RECEIPT = 9
    PREPARE_INPUT = 10


OBJECT_LENGTHS = {
    ObjectKind.NONE: 0,
    ObjectKind.MEASUREMENT: 235,
    ObjectKind.BASELINE_MANIFEST: 117,
    ObjectKind.AUTHORITY_GRANT: 238,
    ObjectKind.PREPARE_AUTHORIZATION: 267,
    ObjectKind.ACTIVATION_AUTHORIZATION: 267,
    ObjectKind.PREPARED_ARTIFACT: 683,
    ObjectKind.PREPARE_ACK: 112,
    ObjectKind.ACTIVATE_ACK: 80,
    ObjectKind.BOOT_RECEIPT: 386,
    ObjectKind.PREPARE_INPUT: 626,
}


class Status(IntEnum):
    OK = 0
    PENDING = 1
    REJECTED_CHANGED_REQUEST = 2
    CHANGED_REQUEST = 2
    DENIED = 3
    BUSY = 4
    MISSING = 5
    CORRUPT = 6
    UNCERTAIN = 7
    OWNERSHIP_DENIED = 8
    NO_CAPACITY = 9


class Reason(IntEnum):
    """Canonical router reasons; other uint16 backend reasons remain opaque."""

    NONE = 0
    NO_BACKEND_BOUND = 1
    UNKNOWN_SUBCOMMAND = 100
    UNSUPPORTED_SUBCOMMAND = 100  # Compatibility name for the router's code 100.
    NO_SESSION = 101
    INVALID_SESSION = (
        101  # Compatibility name; wire reason is the router's NoSession code.
    )
    SESSION_MISMATCH = 102
    OCCUPIED = 103
    ZERO_TICKET = 104
    FOREIGN_TICKET = 105
    BAD_OBJECT_KIND = 106
    OVERFLOW = 107


class CodecErrorCode(IntEnum):
    OK = 0
    INVALID_ARGUMENT = 1
    TRUNCATED_FRAME = 2
    EXTRA_FRAME_BYTES = 3
    INVALID_COMMAND = 4
    UNSUPPORTED_VERSION = 5
    UNSUPPORTED_SUBCOMMAND = 6
    UNSUPPORTED_STATUS = 7
    UNSUPPORTED_REASON = 8
    UNSUPPORTED_OBJECT_KIND = 9
    DATA_LENGTH_MISMATCH = 10
    DATA_TOO_LARGE = 11
    INVALID_SESSION = 12
    INVALID_REQUEST_ID = 13
    INVALID_OPEN_SHAPE = 14
    INVALID_OPERATION_SHAPE = 15
    INVALID_OBJECT_LENGTH = 16
    RANGE_OVERFLOW = 17
    RANGE_OUT_OF_BOUNDS = 18
    INVALID_MEASUREMENT_VERSION = 19
    INVALID_MEASUREMENT_ROLE = 20
    INVALID_BOOT_CONFIG_ID = 21


class MaintenanceCodecError(ValueError):
    """Base class for a typed malformed/unsupported maintenance frame."""

    code = CodecErrorCode.INVALID_ARGUMENT


class TruncatedFrameError(MaintenanceCodecError):
    code = CodecErrorCode.TRUNCATED_FRAME


class ExtraFrameBytesError(MaintenanceCodecError):
    code = CodecErrorCode.EXTRA_FRAME_BYTES


class InvalidCommandError(MaintenanceCodecError):
    code = CodecErrorCode.INVALID_COMMAND


class UnsupportedVersionError(MaintenanceCodecError):
    code = CodecErrorCode.UNSUPPORTED_VERSION


class UnsupportedSubcommandError(MaintenanceCodecError):
    code = CodecErrorCode.UNSUPPORTED_SUBCOMMAND


class UnsupportedStatusError(MaintenanceCodecError):
    code = CodecErrorCode.UNSUPPORTED_STATUS


class UnsupportedReasonError(MaintenanceCodecError):
    code = CodecErrorCode.UNSUPPORTED_REASON


class UnsupportedObjectKindError(MaintenanceCodecError):
    code = CodecErrorCode.UNSUPPORTED_OBJECT_KIND


class DataLengthMismatchError(MaintenanceCodecError):
    code = CodecErrorCode.DATA_LENGTH_MISMATCH


class DataTooLargeError(MaintenanceCodecError):
    code = CodecErrorCode.DATA_TOO_LARGE


class InvalidSessionError(MaintenanceCodecError):
    code = CodecErrorCode.INVALID_SESSION


class InvalidRequestIdError(MaintenanceCodecError):
    code = CodecErrorCode.INVALID_REQUEST_ID


class InvalidOpenShapeError(MaintenanceCodecError):
    code = CodecErrorCode.INVALID_OPEN_SHAPE


class InvalidOperationShapeError(MaintenanceCodecError):
    code = CodecErrorCode.INVALID_OPERATION_SHAPE


class InvalidObjectLengthError(MaintenanceCodecError):
    code = CodecErrorCode.INVALID_OBJECT_LENGTH


class RangeOverflowError(MaintenanceCodecError):
    code = CodecErrorCode.RANGE_OVERFLOW


class RangeOutOfBoundsError(MaintenanceCodecError):
    code = CodecErrorCode.RANGE_OUT_OF_BOUNDS


class InvalidMeasurementVersionError(MaintenanceCodecError):
    code = CodecErrorCode.INVALID_MEASUREMENT_VERSION


class InvalidMeasurementRoleError(MaintenanceCodecError):
    code = CodecErrorCode.INVALID_MEASUREMENT_ROLE


class InvalidBootConfigIdError(MaintenanceCodecError):
    code = CodecErrorCode.INVALID_BOOT_CONFIG_ID


_ERROR_TYPES = {
    e.code: e
    for e in (
        TruncatedFrameError,
        ExtraFrameBytesError,
        InvalidCommandError,
        UnsupportedVersionError,
        UnsupportedSubcommandError,
        UnsupportedStatusError,
        UnsupportedReasonError,
        UnsupportedObjectKindError,
        DataLengthMismatchError,
        DataTooLargeError,
        InvalidSessionError,
        InvalidRequestIdError,
        InvalidOpenShapeError,
        InvalidOperationShapeError,
        InvalidObjectLengthError,
        RangeOverflowError,
        RangeOutOfBoundsError,
        InvalidMeasurementVersionError,
        InvalidMeasurementRoleError,
        InvalidBootConfigIdError,
    )
}


def _fail(code, detail):
    error = _ERROR_TYPES.get(code, MaintenanceCodecError)
    raise error(detail)


def _u32(value, name):
    if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        _fail(CodecErrorCode.INVALID_ARGUMENT, f"{name} is outside uint32")
    return value


def _range(total, offset, length):
    if offset + length > 0xFFFFFFFF:
        _fail(CodecErrorCode.RANGE_OVERFLOW, "offset + length overflows uint32")
    if offset + length > total:
        _fail(CodecErrorCode.RANGE_OUT_OF_BOUNDS, "slice exceeds total")


def _kind(value):
    try:
        return ObjectKind(value)
    except (ValueError, TypeError):
        _fail(CodecErrorCode.UNSUPPORTED_OBJECT_KIND, f"unknown object kind: {value!r}")


def _sub(value):
    try:
        return Subcommand(value)
    except (ValueError, TypeError):
        _fail(CodecErrorCode.UNSUPPORTED_SUBCOMMAND, f"unknown subcommand: {value!r}")


def _session(value):
    if not isinstance(value, bytes) or len(value) != 16:
        _fail(CodecErrorCode.INVALID_SESSION, "session must be 16 bytes")
    return value


def _header_common(command, version, sub, kind):
    if command != COMMAND:
        _fail(CodecErrorCode.INVALID_COMMAND, "wrong command/response byte")
    if version != VERSION:
        _fail(CodecErrorCode.UNSUPPORTED_VERSION, "unsupported protocol version")
    return _sub(sub), _kind(kind)


def _validate_request(r, payload_len):
    sub, kind = _header_common(r.command, r.version, r.subcommand, r.object_kind)
    if payload_len > MAX_DATA:
        _fail(CodecErrorCode.DATA_TOO_LARGE, "payload exceeds 128 bytes")
    if not _u32(r.request_id, "request_id"):
        _fail(CodecErrorCode.INVALID_REQUEST_ID, "request_id must be nonzero")
    _u32(r.job_ticket, "job_ticket")
    total = _u32(r.total, "total")
    off = _u32(r.offset, "offset")
    count = r.data_len
    if not isinstance(count, int) or not 0 <= count <= 255:
        _fail(CodecErrorCode.INVALID_ARGUMENT, "data_len is not uint8")
    if count > MAX_DATA:
        _fail(CodecErrorCode.DATA_TOO_LARGE, "requested/data payload exceeds 128 bytes")
    read = sub == Subcommand.READ_OBJECT
    if payload_len != (0 if read else count):
        _fail(
            CodecErrorCode.DATA_LENGTH_MISMATCH,
            "wire payload length does not match header",
        )
    if sub == Subcommand.OPEN:
        if _session(r.session) != bytes(16) or r.job_ticket != 0:
            _fail(
                CodecErrorCode.INVALID_SESSION, "OPEN requires zero session and ticket"
            )
        if (
            kind != ObjectKind.NONE
            or total != 16
            or off != 0
            or count != 16
            or payload_len != 16
        ):
            _fail(
                CodecErrorCode.INVALID_OPEN_SHAPE,
                "OPEN carries only a 16-byte host challenge",
            )
        return
    if _session(r.session) == bytes(16):
        _fail(
            CodecErrorCode.INVALID_SESSION, "non-OPEN request requires nonzero session"
        )
    if sub == Subcommand.CHALLENGE:
        if (
            r.job_ticket == 0
            or kind
            not in (
                ObjectKind.PREPARE_AUTHORIZATION,
                ObjectKind.ACTIVATION_AUTHORIZATION,
            )
            or total
            or off
            or count
            or payload_len
        ):
            _fail(
                CodecErrorCode.INVALID_OPERATION_SHAPE,
                "CHALLENGE requires a job ticket and prepare/activation purpose kind",
            )
        return
    if sub in (Subcommand.PUT_FRAGMENT, Subcommand.READ_OBJECT):
        if kind == ObjectKind.NONE or total != OBJECT_LENGTHS[kind] or count == 0:
            _fail(
                CodecErrorCode.INVALID_OPERATION_SHAPE,
                "object operation needs a fixed-length nonempty slice",
            )
        _range(total, off, count)
        return
    if kind != ObjectKind.NONE or total or off or count or payload_len:
        _fail(CodecErrorCode.INVALID_OPERATION_SHAPE, "job operation is header-only")


def _validate_reply(r, payload_len):
    if r.response != RESPONSE:
        _fail(CodecErrorCode.INVALID_COMMAND, "wrong response byte")
    if r.version != VERSION:
        _fail(CodecErrorCode.UNSUPPORTED_VERSION, "unsupported protocol version")
    sub = _sub(r.subcommand)
    kind = _kind(r.object_kind)
    if not _u32(r.request_id, "request_id"):
        _fail(CodecErrorCode.INVALID_REQUEST_ID, "reply request_id must be nonzero")
    try:
        Status(r.status)
    except (ValueError, TypeError):
        _fail(CodecErrorCode.UNSUPPORTED_STATUS, "unknown status")
    if not isinstance(r.reason, int) or not 0 <= r.reason <= 0xFFFF:
        _fail(CodecErrorCode.INVALID_ARGUMENT, "reason is not uint16")
    if payload_len > MAX_DATA:
        _fail(CodecErrorCode.DATA_TOO_LARGE, "payload exceeds 128 bytes")
    if r.data_len != payload_len:
        _fail(
            CodecErrorCode.DATA_LENGTH_MISMATCH, "reply data_len differs from payload"
        )
    total = _u32(r.total, "total")
    off = _u32(r.offset, "offset")
    if sub == Subcommand.CHALLENGE and Status(r.status) == Status.OK:
        if payload_len != 16:
            _fail(
                CodecErrorCode.DATA_LENGTH_MISMATCH,
                "successful challenge reply needs 16 bytes",
            )
        if kind != ObjectKind.NONE or total or off:
            _fail(
                CodecErrorCode.INVALID_OPERATION_SHAPE,
                "challenge reply must carry only 16 bytes",
            )
    elif sub == Subcommand.READ_OBJECT and Status(r.status) == Status.OK:
        if kind == ObjectKind.NONE or total != OBJECT_LENGTHS[kind] or not r.data_len:
            _fail(
                CodecErrorCode.INVALID_OBJECT_LENGTH,
                "read reply must match fixed object length",
            )
        _range(total, off, r.data_len)
    elif payload_len == 0:
        if (
            sub == Subcommand.PUT_FRAGMENT
            and kind != ObjectKind.NONE
            and total == OBJECT_LENGTHS[kind]
        ):
            _range(total, off, 0)
        elif total or off:
            _fail(
                CodecErrorCode.INVALID_OPERATION_SHAPE,
                "empty reply has an invalid object range",
            )
    else:
        _fail(CodecErrorCode.INVALID_OPERATION_SHAPE, "unexpected reply payload")


@dataclass
class Request:
    subcommand: Subcommand = Subcommand.OPEN
    session: bytes = bytes(16)
    request_id: int = 0
    job_ticket: int = 0
    object_kind: ObjectKind = ObjectKind.NONE
    total: int = 0
    offset: int = 0
    data_len: int = 0
    data: bytes = b""
    command: int = COMMAND
    version: int = VERSION


@dataclass
class Reply:
    subcommand: Subcommand = Subcommand.OPEN
    status: Status = Status.OK
    reason: Reason = Reason.NONE
    session: bytes = bytes(16)
    request_id: int = 0
    job_ticket: int = 0
    object_kind: ObjectKind = ObjectKind.NONE
    total: int = 0
    offset: int = 0
    data: bytes = b""
    response: int = RESPONSE
    version: int = VERSION
    data_len: int = field(init=False)

    def __post_init__(self):
        self.data_len = len(self.data)


@dataclass
class Measurement:
    uid8: bytes
    full_public_key: bytes
    profile: int
    target: int
    current_role: int
    layout: int
    sdk28_sha256: bytes
    image_extent: int
    image_address: int
    image_sha256: bytes
    image_crc16: int
    loader_start: int
    loader_length: int
    loader_sha256: bytes
    boot_config_id: int
    host_challenge: bytes
    device_nonce: bytes
    raw_sdk28: bytes
    version: int = VERSION


def encode_request(r: Request) -> bytes:
    if not isinstance(r.data, bytes):
        _fail(CodecErrorCode.INVALID_ARGUMENT, "request data must be bytes")
    _validate_request(r, len(r.data))
    return (
        bytes((r.command, int(r.subcommand), r.version))
        + _session(r.session)
        + struct.pack(">II", r.request_id, r.job_ticket)
        + bytes((int(r.object_kind),))
        + struct.pack(">II", r.total, r.offset)
        + bytes((r.data_len,))
        + r.data
    )


def decode_request(frame: bytes) -> Request:
    if not isinstance(frame, bytes):
        _fail(CodecErrorCode.INVALID_ARGUMENT, "frame must be bytes")
    if len(frame) < REQUEST_HEADER_SIZE:
        _fail(CodecErrorCode.TRUNCATED_FRAME, "request header is truncated")
    if len(frame) > MAX_REQUEST:
        _fail(CodecErrorCode.DATA_TOO_LARGE, "request exceeds 165 bytes")
    cmd, sub, ver = frame[0:3]
    session = frame[3:19]
    req, ticket = struct.unpack_from(">II", frame, 19)
    kind = frame[27]
    total, off = struct.unpack_from(">II", frame, 28)
    n = frame[36]
    r = Request(
        sub,
        session,
        req,
        ticket,
        kind,
        total,
        off,
        n,
        frame[37:],
        cmd,
        ver,
    )
    _validate_request(r, len(r.data))
    r.subcommand = Subcommand(sub)
    r.object_kind = ObjectKind(kind)
    return r


def encode_reply(r: Reply) -> bytes:
    if not isinstance(r.data, bytes):
        _fail(CodecErrorCode.INVALID_ARGUMENT, "reply data must be bytes")
    r.data_len = len(r.data)
    _validate_reply(r, len(r.data))
    return (
        bytes((r.response, int(r.subcommand), r.version, int(r.status)))
        + struct.pack(">H", r.reason)
        + _session(r.session)
        + struct.pack(
            ">II", _u32(r.request_id, "request_id"), _u32(r.job_ticket, "job_ticket")
        )
        + bytes((int(r.object_kind),))
        + struct.pack(">II", r.total, r.offset)
        + bytes((r.data_len,))
        + r.data
    )


def decode_reply(frame: bytes) -> Reply:
    if not isinstance(frame, bytes):
        _fail(CodecErrorCode.INVALID_ARGUMENT, "frame must be bytes")
    if len(frame) < REPLY_HEADER_SIZE:
        _fail(CodecErrorCode.TRUNCATED_FRAME, "reply header is truncated")
    if len(frame) > MAX_REPLY:
        _fail(CodecErrorCode.DATA_TOO_LARGE, "reply exceeds 168 bytes")
    resp, sub, ver, status = frame[:4]
    reason = struct.unpack_from(">H", frame, 4)[0]
    session = frame[6:22]
    req, ticket = struct.unpack_from(">II", frame, 22)
    kind = frame[30]
    total, off = struct.unpack_from(">II", frame, 31)
    n = frame[39]
    typed_status = status
    data = frame[40:]
    if n != len(data):
        _fail(
            CodecErrorCode.DATA_LENGTH_MISMATCH, "reply data_len differs from payload"
        )
    r = Reply(
        sub,
        typed_status,
        reason,
        session,
        req,
        ticket,
        kind,
        total,
        off,
        data,
        resp,
        ver,
    )
    _validate_reply(r, len(data))
    r.subcommand = Subcommand(sub)
    r.object_kind = ObjectKind(kind)
    r.status = Status(status)
    return r


def _check_measurement(m):
    if m.version != VERSION:
        _fail(
            CodecErrorCode.INVALID_MEASUREMENT_VERSION, "measurement version must be 1"
        )
    for name, value, size in (
        ("uid8", m.uid8, 8),
        ("full_public_key", m.full_public_key, 32),
        ("sdk28_sha256", m.sdk28_sha256, 32),
        ("image_sha256", m.image_sha256, 32),
        ("loader_sha256", m.loader_sha256, 32),
        ("host_challenge", m.host_challenge, 16),
        ("device_nonce", m.device_nonce, 16),
        ("raw_sdk28", m.raw_sdk28, 28),
    ):
        if not isinstance(value, bytes) or len(value) != size:
            _fail(CodecErrorCode.INVALID_ARGUMENT, f"{name} must be {size} bytes")
    if m.current_role not in (0, 1):
        _fail(CodecErrorCode.INVALID_MEASUREMENT_ROLE, "compiled role must be 0 or 1")
    if m.boot_config_id not in (0x00010001, 0x00010002):
        _fail(
            CodecErrorCode.INVALID_BOOT_CONFIG_ID,
            "boot config id is not an approved selector policy id",
        )
    for name, value in (
        ("profile", m.profile),
        ("target", m.target),
        ("layout", m.layout),
        ("image_extent", m.image_extent),
        ("image_address", m.image_address),
        ("loader_start", m.loader_start),
        ("loader_length", m.loader_length),
        ("boot_config_id", m.boot_config_id),
    ):
        _u32(value, name)
    if not 0 <= m.image_crc16 <= 0xFFFF:
        _fail(CodecErrorCode.INVALID_ARGUMENT, "image_crc16 is not uint16")


def encode_measurement(m: Measurement) -> bytes:
    _check_measurement(m)
    result = (
        bytes((m.version,))
        + m.uid8
        + m.full_public_key
        + struct.pack(">IIII", m.profile, m.target, m.current_role, m.layout)
        + m.sdk28_sha256
        + struct.pack(">II", m.image_extent, m.image_address)
        + m.image_sha256
        + struct.pack(">HII", m.image_crc16, m.loader_start, m.loader_length)
        + m.loader_sha256
        + struct.pack(">I", m.boot_config_id)
        + m.host_challenge
        + m.device_nonce
        + m.raw_sdk28
    )
    if len(result) != MEASUREMENT_SIZE:
        _fail(
            CodecErrorCode.INVALID_ARGUMENT, "measurement layout implementation error"
        )
    return result


def decode_measurement(frame: bytes) -> Measurement:
    if not isinstance(frame, bytes):
        _fail(CodecErrorCode.INVALID_ARGUMENT, "measurement must be bytes")
    if len(frame) < MEASUREMENT_SIZE:
        _fail(CodecErrorCode.TRUNCATED_FRAME, "measurement truncated")
    if len(frame) > MEASUREMENT_SIZE:
        _fail(CodecErrorCode.EXTRA_FRAME_BYTES, "measurement has trailing bytes")
    i = 0
    version = frame[i]
    i += 1
    uid = frame[i : i + 8]
    i += 8
    pub = frame[i : i + 32]
    i += 32
    profile, target, role, layout = struct.unpack_from(">IIII", frame, i)
    i += 16
    sdk = frame[i : i + 32]
    i += 32
    extent, address = struct.unpack_from(">II", frame, i)
    i += 8
    image = frame[i : i + 32]
    i += 32
    crc, loader_start, loader_len = struct.unpack_from(">HII", frame, i)
    i += 10
    loader = frame[i : i + 32]
    i += 32
    config = struct.unpack_from(">I", frame, i)[0]
    i += 4
    challenge = frame[i : i + 16]
    i += 16
    nonce = frame[i : i + 16]
    i += 16
    raw = frame[i : i + 28]
    m = Measurement(
        uid,
        pub,
        profile,
        target,
        role,
        layout,
        sdk,
        extent,
        address,
        image,
        crc,
        loader_start,
        loader_len,
        loader,
        config,
        challenge,
        nonce,
        raw,
        version,
    )
    _check_measurement(m)
    return m
