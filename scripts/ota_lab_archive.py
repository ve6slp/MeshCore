#!/usr/bin/env python3
"""Read-only USB archival for the two authorized nRF52840/XIAO lab boards.

Bounded prerequisite for LoRa OTA hardware commissioning: before any custom
loader/store provisioning touches an authorized board, this tool talks to
the SEPARATE, explicit, USB-only read-only maintenance firmware (see
examples/ota_readonly_archive/) to losslessly archive its physical media,
then (independently, later) lets a caller verify a live board still matches
a previously captured archive.

This tool NEVER:
  - writes/erases/programs/restores anything on the device (there is no
    write opcode in the wire protocol at all, see
    examples/ota_readonly_archive/ReadonlyArchiveProtocol.h);
  - resets, power-cycles, or flashes anything (see scripts/lab_device.py
    for those operations; this tool only ever opens the role's existing,
    already-enumerated serial port);
  - accepts an arbitrary port -- only a role name resolved through
    scripts/lab_device.py's stable-by-id inventory, exactly like every
    other lab tool in this tree;
  - operates on a protected or unrecognized device identity, and it
    refuses BEFORE doing any device I/O, not after;
  - generates production signing/identity key material -- the encryption
    key is a caller-supplied local file, used only to encrypt archives at
    rest; `genkey` below makes a new RANDOM SYMMETRIC file for that sole
    purpose, never a device/mesh identity or OTA signing key;
  - automatically restores/reseeds/rolls back anything from an archive.
    An archive is EVIDENCE ONLY: a snapshot of whatever bytes were on the
    device at capture time. It is never proof that a later-flashed
    diagnostic image (or any other firmware) preserves the original stock
    application. Preserve a validated recovery application separately;
    a diagnostic capture cannot reconstruct an application it replaced.

Command line only ever takes `--role` (an entry in lab/devices.ini's
`[roles]` section), never a raw serial device path.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import time
import zlib
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_device  # noqa: E402  (sys.path must be set up first)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:  # pragma: no cover - environment-dependent, surfaced to the caller.
    AESGCM = None  # type: ignore[assignment]
    InvalidTag = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).resolve().parent.parent
FLASH_CONTRACT_PATH = REPO_ROOT / "src" / "ota" / "platform" / "Nrf52FlashLayoutContract.h"
# Canonical Nordic SDK `bootloader_settings_t` ("SDK28": a fixed 28-byte
# on-flash struct) page location -- read-only reference, never edited here,
# same discipline as FLASH_CONTRACT_PATH above. This tool never guesses this
# address; it is parsed live from the one place this tree already defines
# it, so a future change there cannot silently drift from what gets
# archived as metadata.
BOOTLOADER_LAYOUT_PATH = REPO_ROOT / "bootloader" / "xiao_nrf52840_ota" / "include" / "xiao_ota_layout.h"

# ---------------------------------------------------------------------------
# Wire protocol -- an independent re-implementation of the exact byte layout
# defined in examples/ota_readonly_archive/ReadonlyArchiveProtocol.h. Keep the
# two in lockstep; scripts/tests/test_ota_lab_archive.py asserts the sizes
# below against ones recomputed from these very struct formats, and separately
# exercises a synthetic device that implements this same layout, so any
# accidental drift between the C++ firmware and this file fails a host test
# rather than only failing silently against real hardware.
# ---------------------------------------------------------------------------

MAGIC = b"ROA1"
PROTOCOL_VERSION = 1
DIAGNOSTIC_PROFILE_ID = 0x01
MAX_CHUNK_BYTES = 256
INTERNAL_FLASH_REGION_BYTES = 0x100000
QSPI_REGION_BYTES = 0x200000

OP_IDENTITY = 1
OP_READ = 2

REGION_INTERNAL = 0
REGION_QSPI = 1

STATUS_OK = 0
STATUS_BAD_MAGIC = 1
STATUS_BAD_HEADER_CRC = 2
STATUS_BAD_OPCODE = 3
STATUS_BAD_REGION = 4
STATUS_OUT_OF_RANGE = 5
STATUS_OVERFLOW = 6
STATUS_NOT_INITIALIZED = 7
STATUS_IO_ERROR = 8
STATUS_MALFORMED = 9

STATUS_NAMES = {
    STATUS_OK: "Ok",
    STATUS_BAD_MAGIC: "BadMagic",
    STATUS_BAD_HEADER_CRC: "BadHeaderCrc",
    STATUS_BAD_OPCODE: "BadOpcode",
    STATUS_BAD_REGION: "BadRegion",
    STATUS_OUT_OF_RANGE: "OutOfRange",
    STATUS_OVERFLOW: "Overflow",
    STATUS_NOT_INITIALIZED: "NotInitialized",
    STATUS_IO_ERROR: "IoError",
    STATUS_MALFORMED: "Malformed",
}

_REQUEST_STRUCT = struct.Struct("<4sIBB2sII")  # magic,request_id,opcode,region,reserved,addr,length
REQUEST_FRAME_BYTES = _REQUEST_STRUCT.size + 4  # + header_crc32
_RESPONSE_HEADER_STRUCT = struct.Struct("<4sIBBBBII")  # magic,request_id,status,opcode,region,reserved,addr,length
RESPONSE_PAYLOAD_OFFSET = _RESPONSE_HEADER_STRUCT.size
RESPONSE_FRAME_BYTES = RESPONSE_PAYLOAD_OFFSET + MAX_CHUNK_BYTES + 4 + 4  # + payload_crc32 + frame_crc32


def crc32(data: bytes) -> int:
    # zlib.crc32 is exactly the IEEE 802.3/zlib polynomial CRC-32, seeded
    # 0xFFFFFFFF and finalized with a trailing XOR -- bit-for-bit the same
    # algorithm as ota::storage::Crc32::computeFinalized() used on the
    # firmware side (see src/ota/platform's shared Crc32.h).
    return zlib.crc32(data) & 0xFFFFFFFF


class ProtocolError(RuntimeError):
    """The device responded, but not in a way a caller may trust or accept."""


def build_request(request_id: int, opcode: int, region: int, addr: int, length: int) -> bytes:
    header = _REQUEST_STRUCT.pack(MAGIC, request_id & 0xFFFFFFFF, opcode, region, b"\x00\x00",
                                  addr & 0xFFFFFFFF, length & 0xFFFFFFFF)
    return header + struct.pack("<I", crc32(header))


class ResponseFrame:
    __slots__ = ("request_id", "status", "opcode", "region", "addr", "length", "payload")

    def __init__(self, request_id, status, opcode, region, addr, length, payload):
        self.request_id = request_id
        self.status = status
        self.opcode = opcode
        self.region = region
        self.addr = addr
        self.length = length
        self.payload = payload


def parse_response(raw: bytes) -> ResponseFrame:
    if len(raw) != RESPONSE_FRAME_BYTES:
        raise ProtocolError(f"response frame is {len(raw)} bytes, expected {RESPONSE_FRAME_BYTES}")
    magic, request_id, status, opcode, region, reserved, addr, length = \
        _RESPONSE_HEADER_STRUCT.unpack_from(raw, 0)
    if magic != MAGIC:
        raise ProtocolError("bad response magic (unexpected/stale bytes on the link)")
    if reserved != 0:
        raise ProtocolError("response reserved byte is nonzero")
    payload = raw[RESPONSE_PAYLOAD_OFFSET:RESPONSE_PAYLOAD_OFFSET + MAX_CHUNK_BYTES]
    (payload_crc,) = struct.unpack_from("<I", raw, RESPONSE_PAYLOAD_OFFSET + MAX_CHUNK_BYTES)
    (frame_crc,) = struct.unpack_from("<I", raw, RESPONSE_PAYLOAD_OFFSET + MAX_CHUNK_BYTES + 4)
    computed_frame_crc = crc32(raw[:RESPONSE_PAYLOAD_OFFSET + MAX_CHUNK_BYTES + 4])
    if frame_crc != computed_frame_crc:
        raise ProtocolError("response frame_crc32 mismatch (corrupted/torn frame)")
    if length > MAX_CHUNK_BYTES:
        raise ProtocolError(f"response claims impossible length {length}")
    computed_payload_crc = crc32(payload[:length]) if length else 0
    if payload_crc != computed_payload_crc:
        raise ProtocolError("response payload_crc32 mismatch (corrupted payload)")
    return ResponseFrame(request_id, status, opcode, region, addr, length, payload[:length])


class ReadonlyArchiveLink:
    """Bounded request/response transactions over an already-open serial port.

    `port` only needs `.read(n) -> bytes`, `.write(data) -> int`, and
    (optionally) `.reset_input_buffer()`. Real usage passes a pyserial
    `Serial`; tests pass a synthetic in-process device.
    """

    # Bounded so a wedged/garbage link fails fast instead of scanning forever
    # -- this is a resync budget, not a data size limit.
    _MAX_RESYNC_BYTES = RESPONSE_FRAME_BYTES * 8

    def __init__(self, port, timeout: float = 2.0, retries: int = 3):
        if retries < 1:
            raise ValueError("retries must be >= 1")
        self._port = port
        self._timeout = timeout
        self._retries = retries
        self._next_request_id = 1

    def _read_exact(self, count: int, deadline: float) -> bytes:
        buf = bytearray()
        while len(buf) < count:
            if time.monotonic() > deadline:
                raise TimeoutError(f"timed out waiting for {count} bytes (have {len(buf)})")
            chunk = self._port.read(count - len(buf))
            if chunk:
                buf.extend(chunk)
        return bytes(buf)

    def _resync(self, deadline: float) -> None:
        window = bytearray()
        scanned = 0
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("timed out resyncing to response magic")
            if scanned > self._MAX_RESYNC_BYTES:
                raise ProtocolError("exceeded bounded resync scan without finding response magic")
            chunk = self._port.read(1)
            if not chunk:
                continue
            window += chunk
            scanned += 1
            if len(window) > len(MAGIC):
                del window[: len(window) - len(MAGIC)]
            if bytes(window) == MAGIC:
                return

    def transact(self, opcode: int, region: int, addr: int, length: int) -> ResponseFrame:
        last_error: Optional[Exception] = None
        for _ in range(self._retries):
            request_id = self._next_request_id
            self._next_request_id += 1
            frame = build_request(request_id, opcode, region, addr, length)
            if hasattr(self._port, "reset_input_buffer"):
                self._port.reset_input_buffer()
            written = self._port.write(frame)
            if written != len(frame):
                last_error = ProtocolError(f"short request write: {written}/{len(frame)}")
                continue
            deadline = time.monotonic() + self._timeout
            try:
                self._resync(deadline)
                rest = self._read_exact(RESPONSE_FRAME_BYTES - len(MAGIC), deadline)
            except (TimeoutError, ProtocolError) as exc:
                last_error = exc
                continue
            try:
                response = parse_response(MAGIC + rest)
            except ProtocolError as exc:
                last_error = exc
                continue
            if response.request_id != request_id:
                last_error = ProtocolError(
                    f"stale/reordered response: sent request_id={request_id} got {response.request_id}")
                continue
            if response.opcode != opcode or response.region != region or response.addr != addr:
                last_error = ProtocolError(
                    "response echo mismatch (opcode/region/addr do not match the request sent)")
                continue
            return response
        assert last_error is not None
        raise last_error


class IdentityInfo:
    def __init__(self, uid: bytes, protocol_version: int, profile_id: int,
                internal_size: int, qspi_size: int, qspi_ok: bool, jedec: bytes):
        self.uid = uid
        self.protocol_version = protocol_version
        self.profile_id = profile_id
        self.internal_size = internal_size
        self.qspi_size = qspi_size
        self.qspi_ok = qspi_ok
        self.jedec = jedec

    @property
    def uid_hex(self) -> str:
        return self.uid.hex().upper()

    @property
    def jedec_hex(self) -> str:
        return f"{self.jedec[0]:02X}:{self.jedec[1]:02X}:{self.jedec[2]:02X}"


# Wire size of examples/ota_readonly_archive/main.cpp's buildIdentityPayload():
# 8 (FICR UID) + 1 (protocol_version) + 1 (profile_id) + 4 (internal_size) +
# 4 (qspi_size) + 1 (qspi_ok) + 3 (JEDEC ID) = 22 bytes, EXACTLY -- never
# "at least", since a short-but-still-accepted payload would silently read
# a truncated/zero JEDEC ID as a 2-byte slice instead of failing loudly.
IDENTITY_PAYLOAD_BYTES = 22

# Canonical approved QSPI part for both authorized lab boards: Puya P25Q16H,
# JEDEC ID 85:60:15 -- the exact same approved-ID literal already checked by
# the existing examples/ota_qspi_hardware_test/main.cpp prior art
# (`jedec[0] == 0x85 && jedec[1] == 0x60 && jedec[2] == 0x15`). This tool
# never treats an unrecognized JEDEC ID as an approved 2 MiB part: aliasing
# a different-density chip onto the hardcoded QSPI_REGION_BYTES size would
# silently mark an incomplete/wrong read as a full, valid capture.
APPROVED_QSPI_JEDEC_ID = bytes((0x85, 0x60, 0x15))


def query_identity(link: ReadonlyArchiveLink) -> IdentityInfo:
    response = link.transact(OP_IDENTITY, REGION_INTERNAL, 0, 0)
    if response.status != STATUS_OK:
        raise ProtocolError(f"device refused identity query: {STATUS_NAMES.get(response.status, response.status)}")
    payload = response.payload
    if len(payload) != IDENTITY_PAYLOAD_BYTES:
        raise ProtocolError(
            f"identity payload is {len(payload)} bytes, expected exactly {IDENTITY_PAYLOAD_BYTES} "
            "(firmware/host framing mismatch; refusing rather than parse a short/long payload)")
    uid = payload[0:8]
    protocol_version = payload[8]
    profile_id = payload[9]
    (internal_size,) = struct.unpack_from("<I", payload, 10)
    (qspi_size,) = struct.unpack_from("<I", payload, 14)
    qspi_ok = payload[18] != 0
    jedec = payload[19:22]
    return IdentityInfo(uid, protocol_version, profile_id, internal_size, qspi_size, qspi_ok, jedec)


def read_chunk(link: ReadonlyArchiveLink, region: int, addr: int, length: int) -> bytes:
    response = link.transact(OP_READ, region, addr, length)
    if response.status != STATUS_OK:
        raise ProtocolError(
            f"device refused read region={region} addr={addr:#x} length={length}: "
            f"{STATUS_NAMES.get(response.status, response.status)}")
    if response.length != length:
        raise ProtocolError(
            f"device returned {response.length} bytes for a {length}-byte request "
            f"(region={region} addr={addr:#x}); never substituting a short read as success")
    return response.payload


def read_region(link: ReadonlyArchiveLink, region: int, base_addr: int, total_len: int,
                chunk_bytes: int = MAX_CHUNK_BYTES, progress=None) -> bytes:
    out = bytearray()
    offset = 0
    while offset < total_len:
        length = min(chunk_bytes, total_len - offset)
        out += read_chunk(link, region, base_addr + offset, length)
        offset += length
        if progress is not None:
            progress(offset, total_len)
    return bytes(out)


# ---------------------------------------------------------------------------
# Canonical QSPI sub-region metadata, parsed LIVE from the real contract
# header rather than duplicated as literals -- this is the only way to
# guarantee this tool's region table can never silently drift from
# src/ota/platform/Nrf52FlashLayoutContract.h (the actual OTA partitioning
# owner). See that header for the authoritative comments on each region;
# this tool only reads it, never edits it.
# ---------------------------------------------------------------------------

def _load_flash_contract() -> dict:
    text = FLASH_CONTRACT_PATH.read_text()
    raw = dict(re.findall(r"#define\s+(OTA_NRF52_[A-Z0-9_]+)\s+([^\s]+)", text))
    resolved: dict = {}

    def resolve(name: str, seen: frozenset) -> int:
        if name in resolved:
            return resolved[name]
        if name in seen:
            raise ProtocolError(f"cyclic #define reference resolving {name} in {FLASH_CONTRACT_PATH}")
        if name not in raw:
            raise ProtocolError(f"{FLASH_CONTRACT_PATH} does not define {name}")
        value = raw[name].rstrip("uU")
        if re.fullmatch(r"0[xX][0-9A-Fa-f]+", value):
            result = int(value, 16)
        elif re.fullmatch(r"\d+", value):
            result = int(value, 10)
        elif re.fullmatch(r"OTA_NRF52_[A-Z0-9_]+", value):
            result = resolve(value, seen | {name})
        else:
            raise ProtocolError(f"unsupported #define expression for {name}: {raw[name]!r}")
        resolved[name] = result
        return result

    for name in raw:
        resolve(name, frozenset())
    return resolved


def _load_bootloader_settings_region() -> "tuple[int, int]":
    """Returns (address, size) of Nordic SDK's `bootloader_settings_t` page
    ("SDK28"), parsed LIVE from BOOTLOADER_LAYOUT_PATH's own
    XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS/_RAW_SIZE #defines -- never a
    guessed/hardcoded literal here. The already-captured FULL internal
    dump already contains these bytes; this only names/slices that exact
    canonical window out of it for explicit metadata, it never triggers a
    separate device read.
    """
    text = BOOTLOADER_LAYOUT_PATH.read_text()
    address_match = re.search(r"#define\s+XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS\s+UINT32_C\(([^)]+)\)", text)
    size_match = re.search(r"#define\s+XIAO_OTA_BOOTLOADER_SETTINGS_RAW_SIZE\s+UINT32_C\(([^)]+)\)", text)
    if not address_match or not size_match:
        raise ProtocolError(
            f"{BOOTLOADER_LAYOUT_PATH} no longer defines the expected "
            "XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS/_RAW_SIZE constants; refusing to guess an offset")
    address = int(address_match.group(1), 0)
    size = int(size_match.group(1), 0)
    if size <= 0 or address < 0 or address + size > INTERNAL_FLASH_REGION_BYTES:
        raise ProtocolError("bootloader-settings constant does not fit the internal flash region bound")
    return address, size


def build_region_table() -> "dict[str, tuple[int, int, int]]":
    """name -> (offset, size, media) where media is REGION_INTERNAL/REGION_QSPI."""
    c = _load_flash_contract()
    table = {
        "internal_extrafs": (c["OTA_NRF52_INTERNAL_FS_OFFSET"], c["OTA_NRF52_INTERNAL_FS_SIZE"], REGION_INTERNAL),
        "qspi_candidate": (c["OTA_NRF52_CANDIDATE_OFFSET"], c["OTA_NRF52_CANDIDATE_SIZE"], REGION_QSPI),
        "qspi_security_a": (c["OTA_NRF52_SECURITY_A_OFFSET"], c["OTA_NRF52_SECURITY_A_SIZE"], REGION_QSPI),
        "qspi_backup": (c["OTA_NRF52_BACKUP_OFFSET"], c["OTA_NRF52_BACKUP_SIZE"], REGION_QSPI),
        "qspi_security_b": (c["OTA_NRF52_SECURITY_B_OFFSET"], c["OTA_NRF52_SECURITY_B_SIZE"], REGION_QSPI),
        "qspi_boot_journal": (c["OTA_NRF52_JOURNAL_OFFSET"], c["OTA_NRF52_JOURNAL_SIZE"], REGION_QSPI),
        "qspi_ext_fs": (c["OTA_NRF52_FILESYSTEM_OFFSET"], c["OTA_NRF52_FILESYSTEM_SIZE"], REGION_QSPI),
    }
    settings_addr, settings_size = _load_bootloader_settings_region()
    table["internal_bootloader_settings_sdk28"] = (settings_addr, settings_size, REGION_INTERNAL)
    # Distinguish placement (stride) from writable capacity explicitly, per
    # the contract header's own warning, rather than only trusting the
    # parsed numbers silently.
    if c["OTA_NRF52_BACKUP_OFFSET"] != c["OTA_NRF52_PHYSICAL_BANK_STRIDE_BYTES"]:
        raise ProtocolError("qspi_backup offset no longer equals the physical bank stride constant")
    if c["OTA_NRF52_CANDIDATE_SIZE"] != c["OTA_NRF52_IMAGE_CAPACITY_BYTES"]:
        raise ProtocolError("qspi_candidate size no longer equals the writable image capacity constant")
    for name, (offset, size, media) in table.items():
        bound = INTERNAL_FLASH_REGION_BYTES if media == REGION_INTERNAL else QSPI_REGION_BYTES
        if offset < 0 or size <= 0 or offset + size > bound:
            raise ProtocolError(f"region '{name}' ({offset:#x}+{size:#x}) does not fit its media bound")
    return table


# ---------------------------------------------------------------------------
# Authorized-device resolution. Refuses protected/unknown identities BEFORE
# any device I/O -- this only ever consults lab/devices.ini and udev-derived
# discovery (via scripts/lab_device.py); it never opens the serial port.
# ---------------------------------------------------------------------------

class DeviceRefused(SystemExit):
    pass


def authorized_serial(role: str) -> str:
    protected = lab_device.load_protected()
    protected_serials = set(protected.values())
    roles = lab_device.load_roles()  # already refuses role/protected serial collisions itself.
    if role in protected:
        raise DeviceRefused(f"refusing protected lab device role '{role}'; never a valid archive target")
    if role not in roles:
        known = ", ".join(sorted(roles)) or "<none configured>"
        raise DeviceRefused(f"unknown lab role '{role}'; configured roles: {known}")
    stable_serial = roles[role]
    if stable_serial in protected_serials:
        raise DeviceRefused(f"role '{role}' resolves to a protected serial; refusing")
    return stable_serial


def resolve_authorized_device(role: str):
    stable_serial = authorized_serial(role)
    device = lab_device.resolve(role, mode=lab_device.MODE_APP)
    if device.serial != stable_serial:
        raise DeviceRefused(
            f"role '{role}' enumerated with serial {device.serial}, expected pinned {stable_serial}; refusing")
    if not str(device.by_id).startswith("/dev/serial/by-id/"):
        raise DeviceRefused(f"refusing unstable device path for role '{role}': {device.by_id}")
    return device, stable_serial


def verify_identity_matches(identity: IdentityInfo, role: str, stable_serial: str) -> None:
    if identity.uid_hex != stable_serial.upper():
        raise DeviceRefused(
            f"device UID {identity.uid_hex} does not match role '{role}' pinned serial {stable_serial}; "
            "refusing to archive a device that is not the one lab/devices.ini authorizes")
    if identity.profile_id != DIAGNOSTIC_PROFILE_ID:
        raise DeviceRefused(
            f"device reports diagnostic profile {identity.profile_id:#x}, expected "
            f"{DIAGNOSTIC_PROFILE_ID:#x}; refusing to trust an unrecognized firmware image")
    if identity.protocol_version != PROTOCOL_VERSION:
        raise DeviceRefused(
            f"device reports protocol version {identity.protocol_version}, host expects {PROTOCOL_VERSION}")
    # Size/part checks below apply BEFORE archive AND verify alike, since
    # both paths route through this same function via
    # _connect_and_query_identity(). Never assume an unrecognized/mismatched
    # part is compatible with the hardcoded region sizes -- a wrong-density
    # chip reporting a different real size (or an unrecognized JEDEC ID)
    # must refuse rather than let the hardcoded 2 MiB QSPI read alias a
    # different, smaller/larger part as a complete, valid capture.
    if identity.internal_size != INTERNAL_FLASH_REGION_BYTES:
        raise DeviceRefused(
            f"device reports internal flash size {identity.internal_size:#x}, expected exactly "
            f"{INTERNAL_FLASH_REGION_BYTES:#x}; refusing rather than risk aliasing a different-size part")
    if identity.qspi_ok:
        if identity.qspi_size != QSPI_REGION_BYTES:
            raise DeviceRefused(
                f"device reports QSPI size {identity.qspi_size:#x}, expected exactly "
                f"{QSPI_REGION_BYTES:#x}; refusing rather than risk aliasing a different-density part")
        if identity.jedec != APPROVED_QSPI_JEDEC_ID:
            raise DeviceRefused(
                f"device reports QSPI JEDEC ID {identity.jedec_hex}, expected the approved "
                f"{APPROVED_QSPI_JEDEC_ID[0]:02X}:{APPROVED_QSPI_JEDEC_ID[1]:02X}:"
                f"{APPROVED_QSPI_JEDEC_ID[2]:02X} (P25Q16H); refusing an unrecognized QSPI part rather "
                "than assuming it is the approved 2 MiB density")


# ---------------------------------------------------------------------------
# Archive container: AES-256-GCM authenticated encryption at rest over a
# caller-supplied local key file. Never a production signing/identity key;
# see `cmd_genkey` below for what it actually is.
# ---------------------------------------------------------------------------

ARCHIVE_MAGIC = b"MCOA1"
ARCHIVE_SCHEMA_VERSION = 1
KEY_BYTES = 32
NONCE_BYTES = 12

ARCHIVE_NOTICE = (
    "EVIDENCE ONLY. This archive is a byte-for-byte snapshot captured over "
    "the read-only USB maintenance protocol at the recorded time. It grants "
    "no restore/rollback/reseed authority and must never be used to "
    "automatically restore security counters, tails, floors, SDK header, or "
    "image bytes onto any device. It is also NOT proof that a later-flashed "
    "diagnostic or other firmware preserves the original stock application; "
    "a validated recovery application must be preserved separately."
)


def _require_cryptography() -> None:
    if AESGCM is None:
        raise SystemExit(
            "missing dependency: the 'cryptography' package is required for archive/verify "
            "encryption; install it (e.g. `pip install cryptography`) and re-run")


def load_key(key_path: Path) -> bytes:
    if not key_path.is_file():
        raise SystemExit(f"key file not found: {key_path}")
    mode = key_path.stat().st_mode
    if mode & 0o077:
        raise SystemExit(
            f"refusing to use key file with permissive mode {oct(mode & 0o777)}: {key_path}\n"
            f"restrict it first, e.g. `chmod 600 {key_path}`")
    data = key_path.read_bytes()
    if len(data) != KEY_BYTES:
        raise SystemExit(f"key file must be exactly {KEY_BYTES} raw bytes, got {len(data)}: {key_path}")
    return data


def cmd_genkey(args: argparse.Namespace) -> int:
    """Generate a new LOCAL, SYMMETRIC archive-encryption key.

    This is NOT a device identity key, NOT an OTA signing key, and NOT
    registry/production key material of any kind -- it exists solely to
    encrypt/decrypt archive files produced by this tool, and never leaves
    the local host.
    """
    output = Path(args.output)
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing key file: {output}")
    key = os.urandom(KEY_BYTES)
    fd = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    print(f"wrote new local archive-encryption key: {output}")
    return 0


def _atomic_write(path: Path, data: bytes, *, verify) -> None:
    """Writes `data` to a NEW file under `path`'s directory -- NEVER touching
    `path` itself yet -- calls `verify(temp_bytes)` to fully re-validate the
    just-written bytes from disk, and ONLY THEN atomically publishes them to
    `path` using a no-clobber `os.link()` (never `os.replace()`):

      - a failed `verify()` never disturbs `path` at all: it may not exist
        yet, or may hold unrelated prior evidence from an earlier run --
        either way it is left completely untouched;
      - a file already existing at `path` is refused, never silently
        replaced -- there is no authorized overwrite flag currently;
      - two callers racing for the same `path` cannot both "succeed":
        `os.link()` fails atomically with `FileExistsError` if the
        destination already exists, so there is no separate
        exists()-then-write TOCTOU window for a concurrent racer to win.

    Only ever removes its OWN uniquely-named temp file, on any path
    (success or failure) -- never a broad/blind cleanup of anything else in
    the directory.
    """
    tmp_dir = path.parent
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(tmp_dir))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, 0o600)
        # Full integrity/metadata re-validation of exactly what is on disk,
        # BEFORE path is ever touched -- a bad archive never reaches path.
        verify(tmp_path.read_bytes())
        try:
            os.link(tmp_path, path)
        except FileExistsError:
            raise SystemExit(
                f"refusing to overwrite existing output file: {path} "
                "(no output-overwrite is currently authorized); the existing "
                "file was left completely untouched") from None
    finally:
        try:
            tmp_path.unlink(missing_ok=True)  # only ever this call's own named temp path.
        except OSError:
            pass
    dir_fd = os.open(str(tmp_dir), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def encrypt_archive(key: bytes, metadata: dict, internal_full: bytes, qspi_full: bytes) -> bytes:
    _require_cryptography()
    metadata = dict(metadata)
    metadata["internal_full_len"] = len(internal_full)
    metadata["qspi_full_len"] = len(qspi_full)
    json_bytes = json.dumps(metadata, sort_keys=True).encode("utf-8")
    plaintext = struct.pack(">I", len(json_bytes)) + json_bytes + internal_full + qspi_full
    nonce = os.urandom(NONCE_BYTES)
    aad = ARCHIVE_MAGIC + bytes([ARCHIVE_SCHEMA_VERSION])
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return (ARCHIVE_MAGIC + bytes([ARCHIVE_SCHEMA_VERSION]) + nonce +
            struct.pack(">I", len(ciphertext)) + ciphertext)


def decrypt_archive(key: bytes, raw: bytes) -> tuple:
    _require_cryptography()
    header_len = len(ARCHIVE_MAGIC) + 1 + NONCE_BYTES + 4
    if len(raw) < header_len:
        raise ProtocolError("archive file is too short to be valid (damaged record)")
    if raw[: len(ARCHIVE_MAGIC)] != ARCHIVE_MAGIC:
        raise ProtocolError("archive file has the wrong magic (damaged record)")
    schema = raw[len(ARCHIVE_MAGIC)]
    if schema != ARCHIVE_SCHEMA_VERSION:
        raise ProtocolError(f"unsupported archive schema version {schema} (damaged record)")
    offset = len(ARCHIVE_MAGIC) + 1
    nonce = raw[offset:offset + NONCE_BYTES]
    offset += NONCE_BYTES
    (ciphertext_len,) = struct.unpack_from(">I", raw, offset)
    offset += 4
    # Strict bounds: the declared ciphertext length must account for every
    # remaining byte exactly -- no shorter (truncated) and no longer
    # (unexplained trailing bytes silently ignored/accepted) container.
    if len(raw) - offset != ciphertext_len:
        raise ProtocolError(
            "archive file length does not match its declared ciphertext length "
            "(truncated or has unexpected trailing bytes; damaged record)")
    ciphertext = raw[offset:offset + ciphertext_len]
    aad = ARCHIVE_MAGIC + bytes([schema])
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:  # never leak plaintext or partial decrypt state on failure.
        raise ProtocolError("archive authentication failed (wrong key or corrupted/tampered file)") from exc

    if len(plaintext) < 4:
        raise ProtocolError("archive plaintext is too short to contain metadata (damaged record)")
    (json_len,) = struct.unpack_from(">I", plaintext, 0)
    if json_len == 0 or 4 + json_len > len(plaintext):
        raise ProtocolError("archive plaintext metadata length is out of bounds (damaged record)")
    json_bytes = plaintext[4:4 + json_len]
    try:
        metadata = json.loads(json_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("archive metadata is not valid UTF-8 JSON (damaged record)") from exc
    if not isinstance(metadata, dict):
        raise ProtocolError("archive metadata is not a JSON object (damaged record)")

    if metadata.get("schema") != schema:
        raise ProtocolError(
            "archive metadata 'schema' field does not match its own container schema byte (damaged record)")
    internal_len = metadata.get("internal_full_len")
    qspi_len = metadata.get("qspi_full_len")
    if (not isinstance(internal_len, int) or isinstance(internal_len, bool) or internal_len < 0 or
            not isinstance(qspi_len, int) or isinstance(qspi_len, bool) or qspi_len < 0):
        raise ProtocolError("archive metadata media lengths are missing or not valid non-negative integers")
    for required_key in ("device_uid_hex", "role", "stable_serial"):
        if not isinstance(metadata.get(required_key), str) or not metadata[required_key]:
            raise ProtocolError(f"archive metadata field '{required_key}' is missing or not a non-empty string")

    body = plaintext[4 + json_len:]
    # Strict bounds: the body must be EXACTLY internal_len + qspi_len bytes --
    # never shorter (truncated media) and never longer (unexplained trailing
    # bytes silently dropped by a slice), or this is rejected as damaged.
    if len(body) != internal_len + qspi_len:
        raise ProtocolError(
            "archive body length does not match its own declared media lengths (damaged record)")
    internal_full = body[:internal_len]
    qspi_full = body[internal_len:internal_len + qspi_len]

    # Full schema-completeness + self-consistency re-check. A valid AEAD tag
    # only proves these bytes were produced by the holder of this key -- it
    # does NOT prove the metadata JSON inside actually describes those same
    # bytes correctly or completely. Only applies once the body IS a full
    # mandatory-size capture (a short/partial-capture body is refused by the
    # caller's own explicit, more specific mandatory-full-size check -- see
    # cmd_archive/cmd_verify); this guards against a DIFFERENT failure mode:
    # a full, correctly captured media body paired with wrong, missing, or
    # stale region/identity metadata (e.g. a hand-edited record that omits
    # the SDK28 region, or claims a wrong offset/hash for a named region)
    # that would otherwise still decrypt "successfully".
    if len(internal_full) == INTERNAL_FLASH_REGION_BYTES and len(qspi_full) == QSPI_REGION_BYTES:
        if metadata.get("qspi_captured") is not True:
            raise ProtocolError(
                "archive metadata does not declare a completed full QSPI capture (damaged/incomplete record)")
        if metadata.get("diagnostic_profile_id") != DIAGNOSTIC_PROFILE_ID:
            raise ProtocolError(
                "archive metadata 'diagnostic_profile_id' does not match the expected profile (damaged record)")
        if metadata.get("protocol_version") != PROTOCOL_VERSION:
            raise ProtocolError(
                "archive metadata 'protocol_version' does not match the expected protocol (damaged record)")
        jedec_hex = metadata.get("qspi_jedec_hex")
        if not isinstance(jedec_hex, str) or not re.match(r"^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$", jedec_hex):
            raise ProtocolError("archive metadata 'qspi_jedec_hex' is missing or malformed (damaged record)")
        # Syntax alone is not evidence: a well-formed but WRONG/relabelled
        # JEDEC ID (e.g. "01:02:03") must be refused just as firmly as a
        # malformed one -- this archive must actually decode to the same
        # approved P25Q16H part the live device gate requires, never an
        # arbitrary other well-formed value.
        archived_jedec = bytes(int(b, 16) for b in jedec_hex.split(":"))
        if archived_jedec != APPROVED_QSPI_JEDEC_ID:
            raise ProtocolError(
                f"archive metadata 'qspi_jedec_hex' decodes to {jedec_hex}, not the approved "
                f"{APPROVED_QSPI_JEDEC_ID[0]:02X}:{APPROVED_QSPI_JEDEC_ID[1]:02X}:"
                f"{APPROVED_QSPI_JEDEC_ID[2]:02X} (P25Q16H); refusing a well-formed but unsupported/"
                "relabelled part as evidence")

        internal_claim = metadata.get("internal_full")
        qspi_claim = metadata.get("qspi_full")
        if (not isinstance(internal_claim, dict) or internal_claim.get("size") != INTERNAL_FLASH_REGION_BYTES or
                internal_claim.get("sha256") != sha256_hex(internal_full)):
            raise ProtocolError(
                "archive metadata 'internal_full' size/hash does not match the decrypted media (damaged record)")
        if (not isinstance(qspi_claim, dict) or qspi_claim.get("size") != QSPI_REGION_BYTES or
                qspi_claim.get("sha256") != sha256_hex(qspi_full)):
            raise ProtocolError(
                "archive metadata 'qspi_full' size/hash does not match the decrypted media (damaged record)")

        canonical_regions = region_hashes(build_region_table(), internal_full, qspi_full)
        claimed_regions = metadata.get("regions")
        if not isinstance(claimed_regions, dict) or set(claimed_regions.keys()) != set(canonical_regions.keys()):
            raise ProtocolError(
                "archive metadata 'regions' is missing, incomplete, or does not exactly match the current "
                "canonical region set (damaged/stale record)")
        for name, canonical in canonical_regions.items():
            claimed = claimed_regions.get(name)
            if (not isinstance(claimed, dict) or
                    claimed.get("offset") != canonical["offset"] or
                    claimed.get("size") != canonical["size"] or
                    claimed.get("media") != canonical["media"] or
                    claimed.get("sha256") != canonical["sha256"]):
                raise ProtocolError(
                    f"archive metadata region '{name}' offset/size/media/hash does not match the decrypted "
                    "media against the current canonical region table (damaged/stale record)")

    return metadata, internal_full, qspi_full


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def region_hashes(region_table: dict, internal_full: bytes, qspi_full: bytes) -> dict:
    # Both media buffers MUST be the full, mandatory dump size -- this
    # function never hashes an empty/short buffer's slice as if it were a
    # real named sub-region (that would silently report e.g. a 100 KiB
    # region as an all-zero/empty hash instead of failing loudly).
    if len(internal_full) != INTERNAL_FLASH_REGION_BYTES:
        raise ProtocolError(
            f"internal_full is {len(internal_full)} bytes, not the mandatory full "
            f"{INTERNAL_FLASH_REGION_BYTES}-byte capture; refusing to hash sub-regions")
    if len(qspi_full) != QSPI_REGION_BYTES:
        raise ProtocolError(
            f"qspi_full is {len(qspi_full)} bytes, not the mandatory full "
            f"{QSPI_REGION_BYTES}-byte capture; refusing to hash sub-regions")
    out = {}
    for name, (offset, size, media) in region_table.items():
        buf = internal_full if media == REGION_INTERNAL else qspi_full
        out[name] = {
            "offset": offset,
            "size": size,
            "media": "internal" if media == REGION_INTERNAL else "qspi",
            "sha256": sha256_hex(buf[offset:offset + size]),
        }
    return out


def open_serial_port(by_id_path, timeout: float):
    try:
        import serial  # type: ignore
    except ImportError as exc:
        raise SystemExit("pyserial is required to talk to the archive firmware") from exc
    return serial.Serial(str(by_id_path), 115200, timeout=timeout, write_timeout=timeout)


def _connect_and_query_identity(role: str, args: argparse.Namespace):
    device, stable_serial = resolve_authorized_device(role)
    port = open_serial_port(device.by_id, args.timeout)
    try:
        link = ReadonlyArchiveLink(port, timeout=args.timeout, retries=args.retries)
        identity = query_identity(link)
        verify_identity_matches(identity, role, stable_serial)
        return port, link, identity, stable_serial
    except BaseException:
        port.close()
        raise


def cmd_archive(args: argparse.Namespace) -> int:
    key = load_key(Path(args.key_file))
    region_table = build_region_table()
    port, link, identity, stable_serial = _connect_and_query_identity(args.role, args)
    try:
        if not identity.qspi_ok:
            # This prerequisite MUST always be a FULL 1 MiB internal + 2 MiB
            # QSPI capture, or an explicit failure -- there is no partial-
            # capture escape (no "internal-only" acceptance flag exists).
            raise SystemExit(
                "device reports QSPI not initialized; this prerequisite requires a full "
                f"{INTERNAL_FLASH_REGION_BYTES}-byte internal + {QSPI_REGION_BYTES}-byte QSPI "
                "capture with no partial-capture escape -- refusing to archive")
        internal_full = read_region(link, REGION_INTERNAL, 0, INTERNAL_FLASH_REGION_BYTES)
        qspi_full = read_region(link, REGION_QSPI, 0, QSPI_REGION_BYTES)
    finally:
        port.close()

    # read_region() already never substitutes a short read as success, but
    # assert the exact mandatory full sizes here too, right at the boundary
    # before anything is hashed/encrypted/written.
    if len(internal_full) != INTERNAL_FLASH_REGION_BYTES or len(qspi_full) != QSPI_REGION_BYTES:
        raise SystemExit("device returned a short read for the mandatory full-media capture; refusing to archive")

    metadata = {
        "schema": ARCHIVE_SCHEMA_VERSION,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "diagnostic_profile_id": identity.profile_id,
        "protocol_version": identity.protocol_version,
        "role": args.role,
        "stable_serial": stable_serial,
        "device_uid_hex": identity.uid_hex,
        "qspi_captured": True,
        "qspi_jedec_hex": identity.jedec_hex,
        "internal_full": {"size": INTERNAL_FLASH_REGION_BYTES, "sha256": sha256_hex(internal_full)},
        "qspi_full": {"size": QSPI_REGION_BYTES, "sha256": sha256_hex(qspi_full)},
        "regions": region_hashes(region_table, internal_full, qspi_full),
        "notice": ARCHIVE_NOTICE,
    }
    archive_bytes = encrypt_archive(key, metadata, internal_full, qspi_full)

    def _verify_before_publish(temp_raw: bytes) -> None:
        # Full decrypt + integrity re-check of exactly what was just written
        # to disk, BEFORE the output path is ever touched -- a bad archive
        # never gets published, and any existing file at the output path is
        # never disturbed by a failed check.
        readback_metadata, readback_internal, readback_qspi = decrypt_archive(key, temp_raw)
        if (readback_internal != internal_full or readback_qspi != qspi_full or
                readback_metadata.get("device_uid_hex") != identity.uid_hex):
            raise SystemExit("archive integrity self-check failed before publish; nothing was written")

    output = Path(args.output)
    _atomic_write(output, archive_bytes, verify=_verify_before_publish)

    print(f"archived role={args.role} serial={stable_serial} qspi_captured=True -> {output}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    key = load_key(Path(args.key_file))
    archive_path = Path(args.archive)
    metadata, archived_internal, archived_qspi = decrypt_archive(key, archive_path.read_bytes())
    if len(archived_internal) != INTERNAL_FLASH_REGION_BYTES or len(archived_qspi) != QSPI_REGION_BYTES:
        # Defense in depth: even though cmd_archive() can no longer produce
        # a partial archive, a hand-crafted or otherwise-damaged archive
        # file must still be refused explicitly here, before any device I/O.
        raise SystemExit(
            "archive is not a full-media capture (this prerequisite requires exactly "
            f"{INTERNAL_FLASH_REGION_BYTES} internal + {QSPI_REGION_BYTES} QSPI bytes); "
            "refusing to treat it as valid evidence")

    if args.validate_only:
        stable_serial = authorized_serial(args.role)
        if (metadata["role"] != args.role or metadata["stable_serial"] != stable_serial
                or metadata["device_uid_hex"] != stable_serial.upper()):
            raise DeviceRefused("archive role, serial or device UID does not match the authorized lab role")
        print(f"archive valid role={args.role}: authenticated full-media capture; no live device comparison")
        return 0

    region_table = build_region_table()
    port, link, identity, stable_serial = _connect_and_query_identity(args.role, args)
    try:
        if metadata["device_uid_hex"] != identity.uid_hex:
            raise SystemExit(
                f"archive was captured from device {metadata['device_uid_hex']}, "
                f"live device is {identity.uid_hex}; refusing to compare mismatched devices")
        # Same physical UID is not enough on its own: lab/devices.ini's
        # role<->serial mapping could have been reassigned since the
        # archive was captured (e.g. the same chip re-labelled under a
        # different role name). Require the archive's OWN recorded role and
        # pinned serial to exactly match what THIS invocation resolved --
        # before any media dump -- so a same-UID-but-reassigned-role device
        # is refused rather than silently reported "verify OK" under its
        # new role. The lightweight public identity/INFO query above is
        # fine to have already happened; only the media reads must wait.
        if metadata["role"] != args.role:
            raise SystemExit(
                f"archive was captured under role='{metadata['role']}', but this invocation resolved "
                f"role='{args.role}'; refusing to verify against a reassigned/renamed role")
        if metadata["stable_serial"] != stable_serial:
            raise SystemExit(
                f"archive stable_serial={metadata['stable_serial']} does not match the stable_serial "
                f"{stable_serial} resolved for role='{args.role}'; refusing to verify a reassigned role")
        if not identity.qspi_ok:
            raise SystemExit(
                "device reports QSPI not initialized; cannot verify the mandatory full QSPI "
                "capture against this archive -- refusing")
        # Explicit archived-vs-live JEDEC equality, before any media read.
        # decrypt_archive() already forces the archived ID to decode to
        # APPROVED_QSPI_JEDEC_ID, and verify_identity_matches() (above, via
        # _connect_and_query_identity) already forces the live ID to the
        # same approved constant -- but assert the two observed IDs equal
        # each other directly too, rather than relying only on both
        # separately equalling the same canonical value.
        if metadata["qspi_jedec_hex"] != identity.jedec_hex:
            raise SystemExit(
                f"archive recorded QSPI JEDEC ID {metadata['qspi_jedec_hex']}, live device reports "
                f"{identity.jedec_hex}; refusing to treat these as the same evidence")
        live_internal = read_region(link, REGION_INTERNAL, 0, INTERNAL_FLASH_REGION_BYTES)
        live_qspi = read_region(link, REGION_QSPI, 0, QSPI_REGION_BYTES)
    finally:
        port.close()

    failures = []
    if len(live_internal) != len(archived_internal):
        failures.append(
            f"internal_full length differs: live={len(live_internal)} archived={len(archived_internal)}")
    else:
        mismatch = _first_mismatch(live_internal, archived_internal)
        if mismatch is not None:
            failures.append(f"internal_full differs starting at offset {mismatch:#x}")

    if bool(archived_qspi) != bool(live_qspi) or len(live_qspi) != len(archived_qspi):
        failures.append(
            f"qspi_full length/availability differs: live={len(live_qspi)} archived={len(archived_qspi)}")
    elif live_qspi:
        mismatch = _first_mismatch(live_qspi, archived_qspi)
        if mismatch is not None:
            failures.append(f"qspi_full differs starting at offset {mismatch:#x}")

    live_hashes = region_hashes(region_table, live_internal, live_qspi)
    for name, archived in metadata.get("regions", {}).items():
        live = live_hashes.get(name)
        if live is None:
            failures.append(f"region '{name}' is in the archive but not in the current region table")
            continue
        if archived.get("sha256") != live.get("sha256"):
            failures.append(
                f"region '{name}' sha256 differs: archived={archived.get('sha256')} live={live.get('sha256')}")

    if failures:
        for failure in failures:
            print(f"VERIFY DIFFERENCE: {failure}", file=sys.stderr)
        raise SystemExit(f"verify FAILED for role={args.role} serial={stable_serial}: "
                         f"{len(failures)} difference(s) found (see above); no bytes changed on the device")

    print(f"verify OK role={args.role} serial={stable_serial}: live device matches archive exactly")
    return 0


def _first_mismatch(a: bytes, b: bytes) -> Optional[int]:
    length = min(len(a), len(b))
    for offset in range(0, length, 4096):
        chunk_a = a[offset:offset + 4096]
        chunk_b = b[offset:offset + 4096]
        if chunk_a != chunk_b:
            for i in range(len(chunk_a)):
                if chunk_a[i] != chunk_b[i]:
                    return offset + i
    return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    genkey = sub.add_parser("genkey", help="generate a new local archive-encryption key (not a device/signing key)")
    genkey.add_argument("--output", required=True)
    genkey.set_defaults(func=cmd_genkey)

    def add_common(p):
        p.add_argument("--role", required=True, help="lab role from lab/devices.ini, e.g. client or target")
        p.add_argument("--key-file", required=True, help="local archive-encryption key (see `genkey`)")
        p.add_argument("--timeout", type=float, default=5.0)
        p.add_argument("--retries", type=int, default=3)

    archive = sub.add_parser("archive", help="capture a lossless read-only archive of an authorized lab board")
    add_common(archive)
    archive.add_argument("--output", required=True)
    archive.set_defaults(func=cmd_archive)

    verify = sub.add_parser("verify", help="re-read a live board and compare it to a previously captured archive")
    add_common(verify)
    verify.add_argument("--archive", required=True)
    verify.add_argument("--validate-only", action="store_true",
                        help="authenticate the complete archive and role binding without discovering or opening a board")
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
