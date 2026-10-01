"""Host-only tests for scripts/ota_lab_archive.py.

Exercises the read-only archive/verify tool entirely against a synthetic,
in-process fake device that implements the exact wire protocol declared in
examples/ota_readonly_archive/ReadonlyArchiveProtocol.h (re-derived
independently here, not by calling the module's own encoder, so a bug in the
module's framing cannot silently validate itself). No serial hardware, no
lab devices, no filesystem paths outside the repository's own `.tmp/`.
"""

from __future__ import annotations

import contextlib
import io
import os
import pathlib
import shutil
import struct
import sys
import unittest
import zlib
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import ota_lab_archive  # noqa: E402
import lab_device  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TEST_SCRATCH_ROOT = REPO_ROOT / ".tmp" / "ota-lab-archive-tests"

CLIENT_SERIAL = "4186AE911D94CDB1"
TARGET_SERIAL = "3BE94917B92DC5E9"
PINE_SERIAL = "49C5BAF21EEF44A1"


def _pattern(length: int, seed: int) -> bytes:
    """Fast, deterministic, reproducible synthetic media content."""
    base = bytes(((b * 131 + seed) & 0xFF) for b in range(256))
    tiled = base * ((length // 256) + 1)
    return tiled[:length]


DEFAULT_INTERNAL = _pattern(ota_lab_archive.INTERNAL_FLASH_REGION_BYTES, 0x11)
DEFAULT_QSPI = _pattern(ota_lab_archive.QSPI_REGION_BYTES, 0x77)


class FakeDevice:
    """In-process stand-in for the read-only archive USB firmware.

    Implements examples/ota_readonly_archive/ReadonlyArchiveProtocol.h's
    exact byte layout independently (own struct.pack/unpack + zlib.crc32
    calls), so these tests catch a drift between the host module and the
    protocol, not just a bug the host module and this fixture happen to
    share.
    """

    def __init__(self, uid: bytes, qspi_ok: bool = True, internal_data: bytes = None,
                profile_id: int = None, protocol_version: int = None,
                jedec: bytes = b"\x85\x60\x15", internal_size: int = None, qspi_size: int = None,
                identity_payload_short_by: int = 0):
        self.uid = uid
        self.qspi_ok = qspi_ok
        self.profile_id = ota_lab_archive.DIAGNOSTIC_PROFILE_ID if profile_id is None else profile_id
        self.protocol_version = ota_lab_archive.PROTOCOL_VERSION if protocol_version is None else protocol_version
        self.internal_data = DEFAULT_INTERNAL if internal_data is None else internal_data
        self.qspi_data = DEFAULT_QSPI
        self.jedec = jedec
        self.internal_size = ota_lab_archive.INTERNAL_FLASH_REGION_BYTES if internal_size is None else internal_size
        self.qspi_size = ota_lab_archive.QSPI_REGION_BYTES if qspi_size is None else qspi_size
        self.identity_payload_short_by = identity_payload_short_by
        self._incoming = bytearray()
        self._outgoing = bytearray()
        self.reads_served = 0
        self.refuse_all_reads = False
        # One-shot fault injectors, consumed by the next matching response.
        self.corrupt_next_frame_crc = False
        self.corrupt_next_payload_after_crc = False
        self.duplicate_stale_offset = 0
        self.drop_next_response = False
        self.garbage_before_next_response = b""
        self.short_next_read_by = 0
        self.write_short_by = 0

    # -- port-like interface consumed by ReadonlyArchiveLink --------------
    def reset_input_buffer(self):
        # Mirrors real serial behaviour: flushing the input buffer discards
        # whatever unread response bytes are already sitting there, exactly
        # like ReadonlyArchiveLink.transact() relies on before every attempt.
        self._outgoing.clear()

    def close(self):
        pass

    def write(self, data: bytes) -> int:
        self._incoming += data
        while len(self._incoming) >= ota_lab_archive.REQUEST_FRAME_BYTES:
            frame = bytes(self._incoming[:ota_lab_archive.REQUEST_FRAME_BYTES])
            del self._incoming[:ota_lab_archive.REQUEST_FRAME_BYTES]
            self._handle_request(frame)
        if self.write_short_by:
            short_by, self.write_short_by = self.write_short_by, 0
            return max(0, len(data) - short_by)
        return len(data)

    def read(self, n: int) -> bytes:
        n = min(n, len(self._outgoing))
        out = bytes(self._outgoing[:n])
        del self._outgoing[:n]
        return out

    # -- synthetic firmware behaviour ---------------------------------------
    def _handle_request(self, frame: bytes) -> None:
        magic, request_id, opcode, region, reserved, addr, length = \
            struct.unpack_from("<4sIBB2sII", frame, 0)
        (stored_crc,) = struct.unpack_from("<I", frame, 20)
        header_ok = (magic == ota_lab_archive.MAGIC and reserved == b"\x00\x00" and
                    (zlib.crc32(frame[:20]) & 0xFFFFFFFF) == stored_crc)

        status = ota_lab_archive.STATUS_OK
        payload = b""
        if not header_ok:
            status = ota_lab_archive.STATUS_BAD_HEADER_CRC
        elif opcode not in (ota_lab_archive.OP_IDENTITY, ota_lab_archive.OP_READ):
            status = ota_lab_archive.STATUS_BAD_OPCODE
        elif opcode == ota_lab_archive.OP_IDENTITY:
            if region != ota_lab_archive.REGION_INTERNAL or addr != 0 or length != 0:
                status = ota_lab_archive.STATUS_MALFORMED
            else:
                payload = self._identity_payload()
        else:  # OP_READ
            if self.refuse_all_reads:
                raise AssertionError("FakeDevice received an OP_READ when reads were forbidden for this test")
            if region not in (ota_lab_archive.REGION_INTERNAL, ota_lab_archive.REGION_QSPI):
                status = ota_lab_archive.STATUS_BAD_REGION
            elif length == 0 or length > ota_lab_archive.MAX_CHUNK_BYTES:
                status = ota_lab_archive.STATUS_OVERFLOW
            else:
                bound = (ota_lab_archive.INTERNAL_FLASH_REGION_BYTES if region == ota_lab_archive.REGION_INTERNAL
                        else ota_lab_archive.QSPI_REGION_BYTES)
                if length > bound or addr > bound - length:
                    status = ota_lab_archive.STATUS_OUT_OF_RANGE
                elif region == ota_lab_archive.REGION_QSPI and not self.qspi_ok:
                    status = ota_lab_archive.STATUS_NOT_INITIALIZED
                else:
                    media = self.internal_data if region == ota_lab_archive.REGION_INTERNAL else self.qspi_data
                    payload = media[addr:addr + length]
                    self.reads_served += 1
                    if self.short_next_read_by:
                        payload = payload[:max(0, len(payload) - self.short_next_read_by)]
                        self.short_next_read_by = 0

        response = self._encode_response(request_id, status, opcode, region, addr, payload)

        if self.drop_next_response:
            self.drop_next_response = False
            return
        if self.garbage_before_next_response:
            self._outgoing += self.garbage_before_next_response
            self.garbage_before_next_response = b""
        if self.duplicate_stale_offset:
            # Models a genuinely stale duplicate answer (e.g. the device's
            # own earlier retransmit) arriving ahead of the real one for
            # THIS request, generated inside this very write() call so an
            # already-issued reset_input_buffer() cannot have flushed it.
            stale_id = (request_id - self.duplicate_stale_offset) & 0xFFFFFFFF
            self.duplicate_stale_offset = 0
            self._outgoing += self._encode_response(stale_id, status, opcode, region, addr, payload)
        self._outgoing += response

    def _identity_payload(self) -> bytes:
        payload = bytearray()
        payload += self.uid
        payload.append(self.protocol_version)
        payload.append(self.profile_id)
        payload += struct.pack("<I", self.internal_size)
        payload += struct.pack("<I", self.qspi_size if self.qspi_ok else 0)
        payload.append(1 if self.qspi_ok else 0)
        payload += self.jedec if self.qspi_ok else b"\x00\x00\x00"
        if self.identity_payload_short_by:
            payload = payload[:max(0, len(payload) - self.identity_payload_short_by)]
        return bytes(payload)

    def _encode_response(self, request_id, status, opcode, region, addr, payload: bytes) -> bytes:
        header = struct.pack("<4sIBBBBII", ota_lab_archive.MAGIC, request_id, status, opcode, region, 0,
                            addr, len(payload))
        padded_payload = bytearray(payload + b"\x00" * (ota_lab_archive.MAX_CHUNK_BYTES - len(payload)))
        payload_crc = (zlib.crc32(payload) & 0xFFFFFFFF) if payload else 0
        if self.corrupt_next_payload_after_crc:
            self.corrupt_next_payload_after_crc = False
            padded_payload[0] ^= 0xFF  # invalidate payload without touching the stored payload_crc yet.
        body = header + bytes(padded_payload) + struct.pack("<I", payload_crc)
        frame_crc = zlib.crc32(body) & 0xFFFFFFFF
        if self.corrupt_next_frame_crc:
            self.corrupt_next_frame_crc = False
            frame_crc ^= 0xFFFFFFFF
        return body + struct.pack("<I", frame_crc)


def _link(device: FakeDevice, **kwargs) -> ota_lab_archive.ReadonlyArchiveLink:
    return ota_lab_archive.ReadonlyArchiveLink(device, timeout=kwargs.pop("timeout", 1.0),
                                               retries=kwargs.pop("retries", 3))


class ScratchDirMixin:
    def setUp(self):
        super().setUp()
        TEST_SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
        self.scratch = pathlib.Path(TEST_SCRATCH_ROOT) / f"case-{id(self)}"
        self.scratch.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.scratch, ignore_errors=True)
        super().tearDown()

    def make_key_file(self) -> pathlib.Path:
        key_path = self.scratch / "archive.key"
        with contextlib.ExitStack():
            pass
        import argparse
        ota_lab_archive.cmd_genkey(argparse.Namespace(output=str(key_path)))
        return key_path


class ProtocolFrameShapeTests(unittest.TestCase):
    def test_frame_sizes_are_exactly_as_documented(self):
        self.assertEqual(24, ota_lab_archive.REQUEST_FRAME_BYTES)
        self.assertEqual(284, ota_lab_archive.RESPONSE_FRAME_BYTES)
        # Cross-checks against the protocol header's own documented sizes,
        # kept here as plain literals so drift in either file is caught by
        # a change to one without the other, not silently tolerated.
        self.assertEqual(20 + 256 + 4 + 4, ota_lab_archive.RESPONSE_FRAME_BYTES)

    def test_max_chunk_is_small_bounded_not_a_giant_array(self):
        self.assertLessEqual(ota_lab_archive.MAX_CHUNK_BYTES, 256)

    def test_bad_magic_error_never_dumps_the_raw_stale_bytes(self):
        # A stale flash frame / garbage on the link could contain leftover
        # response bytes from a prior transaction (never secret material,
        # but never something this tool should echo back either) -- the
        # error message must be a generic diagnostic, not `repr()` of the
        # raw bytes it saw.
        raw = b"XXXX" + b"\x00" * (ota_lab_archive.RESPONSE_FRAME_BYTES - 4)
        with self.assertRaises(ota_lab_archive.ProtocolError) as ctx:
            ota_lab_archive.parse_response(raw)
        message = str(ctx.exception)
        self.assertNotIn("XXXX", message)
        self.assertNotIn(repr(raw[:4]), message)


class IdentityQueryTests(unittest.TestCase):
    def test_identity_roundtrip_reports_real_uid_and_profile(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        identity = ota_lab_archive.query_identity(_link(device))
        self.assertEqual(TARGET_SERIAL, identity.uid_hex)
        self.assertEqual(ota_lab_archive.DIAGNOSTIC_PROFILE_ID, identity.profile_id)
        self.assertEqual(ota_lab_archive.PROTOCOL_VERSION, identity.protocol_version)
        self.assertTrue(identity.qspi_ok)
        self.assertEqual(ota_lab_archive.INTERNAL_FLASH_REGION_BYTES, identity.internal_size)
        self.assertEqual(ota_lab_archive.QSPI_REGION_BYTES, identity.qspi_size)
        self.assertEqual("85:60:15", identity.jedec_hex)

    def test_identity_reflects_qspi_not_ready(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL), qspi_ok=False)
        identity = ota_lab_archive.query_identity(_link(device))
        self.assertFalse(identity.qspi_ok)
        self.assertEqual(0, identity.qspi_size)

    def test_identity_payload_wrong_size_is_rejected_not_silently_truncated(self):
        # Firmware's real buildIdentityPayload() always emits exactly 22
        # bytes; a 21-byte (or shorter) payload must never be accepted --
        # a permissive "at least" check would silently parse a truncated
        # 2-byte JEDEC slice instead of the real 3-byte field.
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL), identity_payload_short_by=1)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "expected exactly 22"):
            ota_lab_archive.query_identity(_link(device))


class ApprovedPartAndSizeGateTests(unittest.TestCase):
    def test_wrong_internal_size_is_refused(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL),
                            internal_size=ota_lab_archive.INTERNAL_FLASH_REGION_BYTES // 2)
        identity = ota_lab_archive.query_identity(_link(device))
        with self.assertRaisesRegex(ota_lab_archive.DeviceRefused, "internal flash size"):
            ota_lab_archive.verify_identity_matches(identity, "target", TARGET_SERIAL)

    def test_wrong_qspi_size_aliasing_a_different_density_is_refused(self):
        # A different-density QSPI part could still report qspi_ok=True
        # while actually only backing e.g. 1 MiB -- must never let the
        # hardcoded 2 MiB read silently alias it as a complete capture.
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL),
                            qspi_size=ota_lab_archive.QSPI_REGION_BYTES // 2)
        identity = ota_lab_archive.query_identity(_link(device))
        with self.assertRaisesRegex(ota_lab_archive.DeviceRefused, "QSPI size"):
            ota_lab_archive.verify_identity_matches(identity, "target", TARGET_SERIAL)

    def test_unapproved_jedec_id_is_refused_no_permissive_fallback(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL), jedec=b"\xEF\x40\x18")  # a different, real part.
        identity = ota_lab_archive.query_identity(_link(device))
        with self.assertRaisesRegex(ota_lab_archive.DeviceRefused, "JEDEC ID"):
            ota_lab_archive.verify_identity_matches(identity, "target", TARGET_SERIAL)

    def test_approved_p25q16h_part_is_accepted(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL), jedec=b"\x85\x60\x15")
        identity = ota_lab_archive.query_identity(_link(device))
        ota_lab_archive.verify_identity_matches(identity, "target", TARGET_SERIAL)  # must not raise.


class ReadBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        self.link = _link(self.device)

    def test_exact_upper_boundary_of_internal_region_is_readable(self):
        addr = ota_lab_archive.INTERNAL_FLASH_REGION_BYTES - ota_lab_archive.MAX_CHUNK_BYTES
        data = ota_lab_archive.read_chunk(self.link, ota_lab_archive.REGION_INTERNAL, addr,
                                          ota_lab_archive.MAX_CHUNK_BYTES)
        self.assertEqual(DEFAULT_INTERNAL[addr:addr + ota_lab_archive.MAX_CHUNK_BYTES], data)

    def test_one_byte_past_upper_boundary_is_out_of_range(self):
        addr = ota_lab_archive.INTERNAL_FLASH_REGION_BYTES - ota_lab_archive.MAX_CHUNK_BYTES + 1
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "OutOfRange"):
            ota_lab_archive.read_chunk(self.link, ota_lab_archive.REGION_INTERNAL, addr,
                                       ota_lab_archive.MAX_CHUNK_BYTES)

    def test_exact_lower_boundary_addr_zero_is_readable(self):
        data = ota_lab_archive.read_chunk(self.link, ota_lab_archive.REGION_QSPI, 0, ota_lab_archive.MAX_CHUNK_BYTES)
        self.assertEqual(DEFAULT_QSPI[:ota_lab_archive.MAX_CHUNK_BYTES], data)

    def test_qspi_upper_boundary_exact(self):
        addr = ota_lab_archive.QSPI_REGION_BYTES - ota_lab_archive.MAX_CHUNK_BYTES
        data = ota_lab_archive.read_chunk(self.link, ota_lab_archive.REGION_QSPI, addr, ota_lab_archive.MAX_CHUNK_BYTES)
        self.assertEqual(DEFAULT_QSPI[addr:], data)

    def test_zero_length_read_is_rejected_not_silently_empty(self):
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "Overflow"):
            ota_lab_archive.read_chunk(self.link, ota_lab_archive.REGION_INTERNAL, 0, 0)

    def test_over_max_chunk_length_is_rejected(self):
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "Overflow"):
            ota_lab_archive.read_chunk(self.link, ota_lab_archive.REGION_INTERNAL, 0,
                                       ota_lab_archive.MAX_CHUNK_BYTES + 1)

    def test_bad_region_value_is_rejected(self):
        response = self.link.transact(ota_lab_archive.OP_READ, 7, 0, 16)
        self.assertEqual(ota_lab_archive.STATUS_BAD_REGION, response.status)

    def test_unknown_opcode_is_rejected(self):
        response = self.link.transact(99, ota_lab_archive.REGION_INTERNAL, 0, 0)
        self.assertEqual(ota_lab_archive.STATUS_BAD_OPCODE, response.status)

    def test_qspi_not_initialized_is_refused_not_faked_as_zeros(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL), qspi_ok=False)
        link = _link(device)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "NotInitialized"):
            ota_lab_archive.read_chunk(link, ota_lab_archive.REGION_QSPI, 0, 16)

    def test_full_internal_region_read_is_byte_exact(self):
        data = ota_lab_archive.read_region(self.link, ota_lab_archive.REGION_INTERNAL, 0,
                                           ota_lab_archive.INTERNAL_FLASH_REGION_BYTES)
        self.assertEqual(DEFAULT_INTERNAL, data)


class RobustnessTests(unittest.TestCase):
    def test_corrupted_frame_crc_is_rejected_and_retried(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device.corrupt_next_frame_crc = True
        link = _link(device, retries=2)
        # First attempt corrupted, second attempt (a genuinely fresh request) succeeds.
        response = link.transact(ota_lab_archive.OP_IDENTITY, ota_lab_archive.REGION_INTERNAL, 0, 0)
        self.assertEqual(ota_lab_archive.STATUS_OK, response.status)

    def test_corrupted_frame_crc_with_no_retries_left_raises(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device.corrupt_next_frame_crc = True
        link = _link(device, retries=1)
        with self.assertRaises(ota_lab_archive.ProtocolError):
            link.transact(ota_lab_archive.OP_IDENTITY, ota_lab_archive.REGION_INTERNAL, 0, 0)

    def test_payload_crc_mismatch_detected_independently_of_frame_crc(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device.corrupt_next_payload_after_crc = True
        link = _link(device, retries=1)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "payload_crc32"):
            ota_lab_archive.read_chunk(link, ota_lab_archive.REGION_INTERNAL, 0, 16)

    def test_reordered_stale_response_is_discarded_not_accepted(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device.duplicate_stale_offset = 1  # emits one stale duplicate ahead of the first real response.
        link = _link(device, retries=2)
        # First attempt's response stream is [stale, real]; the stale frame
        # mismatches and is discarded, reset_input_buffer() before the retry
        # flushes the still-unread real one too, and the second attempt's
        # own fresh response succeeds cleanly.
        response = link.transact(ota_lab_archive.OP_IDENTITY, ota_lab_archive.REGION_INTERNAL, 0, 0)
        self.assertEqual(ota_lab_archive.STATUS_OK, response.status)

    def test_reordering_with_no_retries_left_raises_not_a_stale_success(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device.duplicate_stale_offset = 1
        link = _link(device, retries=1)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "stale/reordered"):
            link.transact(ota_lab_archive.OP_IDENTITY, ota_lab_archive.REGION_INTERNAL, 0, 0)

    def test_short_request_write_is_never_treated_as_a_sent_request(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device.write_short_by = 1
        link = _link(device, retries=1)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "short request write"):
            link.transact(ota_lab_archive.OP_IDENTITY, ota_lab_archive.REGION_INTERNAL, 0, 0)

    def test_device_returning_wrong_length_is_rejected_not_substituted(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device.short_next_read_by = 4
        link = _link(device, retries=1)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "never substituting"):
            ota_lab_archive.read_chunk(link, ota_lab_archive.REGION_INTERNAL, 0, 16)


class RegionTableTests(unittest.TestCase):
    def test_canonical_region_table_matches_flash_layout_contract(self):
        table = ota_lab_archive.build_region_table()
        self.assertEqual((0xD4000, 0x19000, ota_lab_archive.REGION_INTERNAL), table["internal_extrafs"])
        self.assertEqual((0x000000, 0xAD000, ota_lab_archive.REGION_QSPI), table["qspi_candidate"])
        self.assertEqual((0x0AD000, 0x19000, ota_lab_archive.REGION_QSPI), table["qspi_security_a"])
        self.assertEqual((0x0C6000, 0xAD000, ota_lab_archive.REGION_QSPI), table["qspi_backup"])
        self.assertEqual((0x173000, 0x19000, ota_lab_archive.REGION_QSPI), table["qspi_security_b"])
        self.assertEqual((0x18C000, 0x008000, ota_lab_archive.REGION_QSPI), table["qspi_boot_journal"])
        self.assertEqual((0x194000, 0x06C000, ota_lab_archive.REGION_QSPI), table["qspi_ext_fs"])
        # Explicitly distinguish capacity (0xAD000) from physical stride
        # (0xC6000): the backup bank's offset equals the stride, not the
        # candidate's own capacity.
        candidate_offset, candidate_size, _ = table["qspi_candidate"]
        backup_offset, _, _ = table["qspi_backup"]
        self.assertEqual(0xAD000, candidate_size)
        self.assertEqual(0xC6000, backup_offset)
        self.assertNotEqual(candidate_size, backup_offset)

    def test_bootloader_settings_sdk28_uses_the_canonical_constant_not_a_guess(self):
        # Parsed live from bootloader/xiao_nrf52840_ota/include/xiao_ota_layout.h's
        # own XIAO_OTA_BOOTLOADER_SETTINGS_ADDRESS/_RAW_SIZE -- never a
        # hardcoded/guessed literal in this file. 0xFF000 here is only an
        # assertion cross-checking that live-parsed value, the same way the
        # other canonical constants above are cross-checked, not a
        # fallback this tool would use if the header's value ever changed.
        table = ota_lab_archive.build_region_table()
        address, size, media = table["internal_bootloader_settings_sdk28"]
        self.assertEqual(0x000FF000, address)
        self.assertEqual(28, size)
        self.assertEqual(ota_lab_archive.REGION_INTERNAL, media)
        # Must not overlap the internal ExtraFS window.
        extrafs_offset, extrafs_size, _ = table["internal_extrafs"]
        self.assertFalse(extrafs_offset <= address < extrafs_offset + extrafs_size)

    def test_bootloader_settings_sdk28_missing_constant_is_refused_not_guessed(self):
        with mock.patch.object(ota_lab_archive, "BOOTLOADER_LAYOUT_PATH",
                               pathlib.Path("/nonexistent/xiao_ota_layout.h")):
            with self.assertRaises(Exception):
                ota_lab_archive._load_bootloader_settings_region()

    def test_named_regions_are_contiguous_and_exactly_cover_qspi(self):
        table = ota_lab_archive.build_region_table()
        qspi_regions = sorted((offset, size) for name, (offset, size, media) in table.items()
                              if media == ota_lab_archive.REGION_QSPI)
        expected_start = 0
        for offset, size in qspi_regions:
            self.assertEqual(expected_start, offset)
            expected_start += size
        self.assertEqual(ota_lab_archive.QSPI_REGION_BYTES, expected_start)

    def test_region_hashes_refuses_short_internal_buffer_not_empty_slice(self):
        table = ota_lab_archive.build_region_table()
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "internal_full"):
            ota_lab_archive.region_hashes(table, b"", DEFAULT_QSPI)

    def test_region_hashes_refuses_short_qspi_buffer_not_empty_slice(self):
        table = ota_lab_archive.build_region_table()
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "qspi_full"):
            ota_lab_archive.region_hashes(table, DEFAULT_INTERNAL, b"")

    def test_region_hashes_never_returns_none_for_a_full_capture(self):
        table = ota_lab_archive.build_region_table()
        hashes = ota_lab_archive.region_hashes(table, DEFAULT_INTERNAL, DEFAULT_QSPI)
        for name, entry in hashes.items():
            self.assertIsNotNone(entry["sha256"], f"region '{name}' unexpectedly hashed as empty")


class AuthorizedDeviceResolutionTests(unittest.TestCase):
    def _roles(self):
        return {"client": CLIENT_SERIAL, "target": TARGET_SERIAL}

    def _protected(self):
        return {"pine": PINE_SERIAL}

    def test_protected_role_refused_before_any_serial_open(self):
        with mock.patch.object(lab_device, "load_protected", return_value=self._protected()), \
                mock.patch.object(lab_device, "load_roles", return_value=self._roles()), \
                mock.patch.object(ota_lab_archive, "open_serial_port") as open_port:
            with self.assertRaisesRegex(ota_lab_archive.DeviceRefused, "protected"):
                ota_lab_archive.resolve_authorized_device("pine")
            open_port.assert_not_called()

    def test_unknown_role_refused_before_any_serial_open(self):
        with mock.patch.object(lab_device, "load_protected", return_value=self._protected()), \
                mock.patch.object(lab_device, "load_roles", return_value=self._roles()), \
                mock.patch.object(ota_lab_archive, "open_serial_port") as open_port:
            with self.assertRaisesRegex(ota_lab_archive.DeviceRefused, "unknown lab role"):
                ota_lab_archive.resolve_authorized_device("not-a-role")
            open_port.assert_not_called()

    def test_authorized_role_resolves_via_stable_by_id_path(self):
        device = mock.Mock(serial=TARGET_SERIAL, by_id=pathlib.Path("/dev/serial/by-id/authorized-target"))
        with mock.patch.object(lab_device, "load_protected", return_value=self._protected()), \
                mock.patch.object(lab_device, "load_roles", return_value=self._roles()), \
                mock.patch.object(lab_device, "resolve", return_value=device) as resolve:
            resolved, stable_serial = ota_lab_archive.resolve_authorized_device("target")
        resolve.assert_called_once_with("target", mode=lab_device.MODE_APP)
        self.assertEqual(TARGET_SERIAL, stable_serial)
        self.assertIs(device, resolved)

    def test_enumerated_serial_mismatch_refused(self):
        device = mock.Mock(serial="0000000000000000", by_id=pathlib.Path("/dev/serial/by-id/authorized-target"))
        with mock.patch.object(lab_device, "load_protected", return_value=self._protected()), \
                mock.patch.object(lab_device, "load_roles", return_value=self._roles()), \
                mock.patch.object(lab_device, "resolve", return_value=device):
            with self.assertRaisesRegex(ota_lab_archive.DeviceRefused, "expected pinned"):
                ota_lab_archive.resolve_authorized_device("target")

    def test_uid_mismatch_refused_before_any_media_read(self):
        device = FakeDevice(uid=bytes.fromhex("0000000000000000"))
        device.refuse_all_reads = True  # any OP_READ raises inside the fixture -- proves none happened.
        link = _link(device)
        identity = ota_lab_archive.query_identity(link)
        with self.assertRaisesRegex(ota_lab_archive.DeviceRefused, "does not match role"):
            ota_lab_archive.verify_identity_matches(identity, "target", TARGET_SERIAL)

    def test_unrecognized_profile_id_refused(self):
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL), profile_id=0x02)
        identity = ota_lab_archive.query_identity(_link(device))
        with self.assertRaisesRegex(ota_lab_archive.DeviceRefused, "diagnostic profile"):
            ota_lab_archive.verify_identity_matches(identity, "target", TARGET_SERIAL)


class AtomicWriteTests(ScratchDirMixin, unittest.TestCase):
    """Directly exercises _atomic_write()'s no-clobber/verify-before-publish
    contract, independent of the archive/verify CLI commands."""

    def test_refuses_to_overwrite_an_existing_output_path_by_default(self):
        target = self.scratch / "out.bin"
        target.write_bytes(b"PRIOR-EVIDENCE")
        with self.assertRaisesRegex(SystemExit, "refusing to overwrite"):
            ota_lab_archive._atomic_write(target, b"NEW-DATA", verify=lambda raw: None)
        # The pre-existing file must be completely untouched, not truncated
        # or partially overwritten before the refusal was raised.
        self.assertEqual(b"PRIOR-EVIDENCE", target.read_bytes())

    def test_failed_verify_never_creates_the_output_path(self):
        target = self.scratch / "out.bin"

        def _always_fails(raw):
            raise SystemExit("synthetic integrity failure")

        with self.assertRaisesRegex(SystemExit, "synthetic integrity failure"):
            ota_lab_archive._atomic_write(target, b"NEW-DATA", verify=_always_fails)
        self.assertFalse(target.exists())

    def test_failed_verify_never_disturbs_a_pre_existing_output_path(self):
        target = self.scratch / "out.bin"
        target.write_bytes(b"PRIOR-EVIDENCE")

        def _always_fails(raw):
            raise SystemExit("synthetic integrity failure")

        with self.assertRaisesRegex(SystemExit, "synthetic integrity failure"):
            ota_lab_archive._atomic_write(target, b"NEW-DATA", verify=_always_fails)
        self.assertEqual(b"PRIOR-EVIDENCE", target.read_bytes())

    def test_successful_write_only_leaves_its_own_named_temp_file_cleaned_up(self):
        target = self.scratch / "out.bin"
        ota_lab_archive._atomic_write(target, b"NEW-DATA", verify=lambda raw: None)
        self.assertEqual(b"NEW-DATA", target.read_bytes())
        # No leftover temp files (own-named or otherwise) in the directory.
        leftovers = [p for p in self.scratch.iterdir() if p != target]
        self.assertEqual([], leftovers, f"unexpected leftover files: {leftovers}")

    def test_successful_write_is_restrictively_permissioned(self):
        target = self.scratch / "out.bin"
        ota_lab_archive._atomic_write(target, b"NEW-DATA", verify=lambda raw: None)
        self.assertEqual(0o600, target.stat().st_mode & 0o777)

    def test_verify_callback_receives_exactly_the_bytes_written(self):
        target = self.scratch / "out.bin"
        seen = {}

        def _capture(raw):
            seen["raw"] = raw

        ota_lab_archive._atomic_write(target, b"EXACT-BYTES", verify=_capture)
        self.assertEqual(b"EXACT-BYTES", seen["raw"])


class KeyFileTests(ScratchDirMixin, unittest.TestCase):
    def test_genkey_writes_restrictive_permissions_and_refuses_overwrite(self):
        key_path = self.scratch / "archive.key"
        import argparse
        self.assertEqual(0, ota_lab_archive.cmd_genkey(argparse.Namespace(output=str(key_path))))
        self.assertEqual(32, key_path.stat().st_size)
        self.assertEqual(0o600, key_path.stat().st_mode & 0o777)
        with self.assertRaises(SystemExit):
            ota_lab_archive.cmd_genkey(argparse.Namespace(output=str(key_path)))

    def test_permissive_key_file_is_refused(self):
        key_path = self.scratch / "loose.key"
        key_path.write_bytes(os.urandom(32))
        key_path.chmod(0o644)
        with self.assertRaises(SystemExit):
            ota_lab_archive.load_key(key_path)

    def test_wrong_size_key_file_is_refused(self):
        key_path = self.scratch / "short.key"
        key_path.write_bytes(os.urandom(16))
        key_path.chmod(0o600)
        with self.assertRaises(SystemExit):
            ota_lab_archive.load_key(key_path)


class ArchiveCryptoRoundTripTests(ScratchDirMixin, unittest.TestCase):
    def _full_metadata(self, **extra):
        base = {
            "schema": ota_lab_archive.ARCHIVE_SCHEMA_VERSION,
            "role": "target",
            "stable_serial": TARGET_SERIAL,
            "device_uid_hex": TARGET_SERIAL,
        }
        base.update(extra)
        return base

    def test_encrypt_then_decrypt_round_trips_exact_media_and_metadata(self):
        key = os.urandom(32)
        # Uses the full mandatory 1 MiB/2 MiB media sizes (not a smaller
        # substitute) so this test exercises the same exact-length bounds
        # decrypt_archive() enforces for every real archive/verify call --
        # including the full schema-completeness cross-check (region
        # names/offsets/sizes/hashes recomputed from these same bytes
        # against the CURRENT canonical region table), so this metadata
        # must be a genuinely complete, self-consistent record, not just
        # the minimal identity fields.
        region_table = ota_lab_archive.build_region_table()
        metadata = self._full_metadata(
            diagnostic_profile_id=ota_lab_archive.DIAGNOSTIC_PROFILE_ID,
            protocol_version=ota_lab_archive.PROTOCOL_VERSION,
            qspi_captured=True,
            qspi_jedec_hex="85:60:15",
            internal_full={"size": len(DEFAULT_INTERNAL), "sha256": ota_lab_archive.sha256_hex(DEFAULT_INTERNAL)},
            qspi_full={"size": len(DEFAULT_QSPI), "sha256": ota_lab_archive.sha256_hex(DEFAULT_QSPI)},
            regions=ota_lab_archive.region_hashes(region_table, DEFAULT_INTERNAL, DEFAULT_QSPI),
        )
        blob = ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)
        recovered_metadata, recovered_internal, recovered_qspi = ota_lab_archive.decrypt_archive(key, blob)
        self.assertEqual(DEFAULT_INTERNAL, recovered_internal)
        self.assertEqual(DEFAULT_QSPI, recovered_qspi)
        self.assertEqual("target", recovered_metadata["role"])

    def test_wrong_key_is_denied_without_leaking_plaintext(self):
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        blob = ota_lab_archive.encrypt_archive(key, self._full_metadata(), b"secret-internal", b"secret-qspi")
        with self.assertRaises(ota_lab_archive.ProtocolError) as ctx:
            ota_lab_archive.decrypt_archive(wrong_key, blob)
        message = str(ctx.exception)
        self.assertNotIn("secret-internal", message)
        self.assertNotIn("secret-qspi", message)
        self.assertIn("authentication failed", message)

    def test_wrong_key_raises_because_of_invalid_tag_not_a_generic_except(self):
        # decrypt_archive() must catch the SPECIFIC cryptography.InvalidTag
        # exception, not a bare `except Exception`, so a genuine programming
        # bug elsewhere (e.g. a TypeError) is never mis-reported as "wrong
        # key/corrupted file".
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        blob = ota_lab_archive.encrypt_archive(key, self._full_metadata(), b"abc", b"def")
        with self.assertRaises(ota_lab_archive.ProtocolError) as ctx:
            ota_lab_archive.decrypt_archive(wrong_key, blob)
        self.assertIsInstance(ctx.exception.__cause__, ota_lab_archive.InvalidTag)

    def test_tampered_archive_bytes_are_denied(self):
        key = os.urandom(32)
        blob = bytearray(ota_lab_archive.encrypt_archive(key, self._full_metadata(), b"abc", b"def"))
        blob[-1] ^= 0xFF  # corrupt a ciphertext/tag byte.
        with self.assertRaises(ota_lab_archive.ProtocolError):
            ota_lab_archive.decrypt_archive(key, bytes(blob))

    def test_trailing_bytes_appended_after_ciphertext_are_rejected(self):
        key = os.urandom(32)
        blob = ota_lab_archive.encrypt_archive(key, self._full_metadata(), b"abc", b"def")
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "trailing bytes"):
            ota_lab_archive.decrypt_archive(key, blob + b"\x00\x00\x00\x00")

    def test_truncated_ciphertext_is_rejected_not_silently_shortened(self):
        key = os.urandom(32)
        blob = ota_lab_archive.encrypt_archive(key, self._full_metadata(), b"abc", b"def")
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "trailing bytes"):
            ota_lab_archive.decrypt_archive(key, blob[:-1])

    def test_media_length_metadata_wrong_type_is_rejected(self):
        key = os.urandom(32)
        metadata = self._full_metadata(internal_full_len="3", qspi_full_len=3)
        json_bytes = ota_lab_archive.json.dumps(metadata, sort_keys=True).encode("utf-8")
        plaintext = ota_lab_archive.struct.pack(">I", len(json_bytes)) + json_bytes + b"abc" + b"def"
        nonce = os.urandom(ota_lab_archive.NONCE_BYTES)
        aad = ota_lab_archive.ARCHIVE_MAGIC + bytes([ota_lab_archive.ARCHIVE_SCHEMA_VERSION])
        ciphertext = ota_lab_archive.AESGCM(key).encrypt(nonce, plaintext, aad)
        blob = (ota_lab_archive.ARCHIVE_MAGIC + bytes([ota_lab_archive.ARCHIVE_SCHEMA_VERSION]) + nonce +
                ota_lab_archive.struct.pack(">I", len(ciphertext)) + ciphertext)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "not valid non-negative integers"):
            ota_lab_archive.decrypt_archive(key, blob)

    def test_body_length_not_matching_declared_media_lengths_is_rejected(self):
        # encrypt_archive() always sets internal_full_len/qspi_full_len from
        # the ACTUAL bytes passed in, so to simulate a damaged/hand-edited
        # record we build the container by hand with a lie in the metadata.
        key = os.urandom(32)
        metadata = self._full_metadata(internal_full_len=999, qspi_full_len=1)
        json_bytes = ota_lab_archive.json.dumps(metadata, sort_keys=True).encode("utf-8")
        plaintext = ota_lab_archive.struct.pack(">I", len(json_bytes)) + json_bytes + b"abc" + b"d"
        nonce = os.urandom(ota_lab_archive.NONCE_BYTES)
        aad = ota_lab_archive.ARCHIVE_MAGIC + bytes([ota_lab_archive.ARCHIVE_SCHEMA_VERSION])
        ciphertext = ota_lab_archive.AESGCM(key).encrypt(nonce, plaintext, aad)
        blob = (ota_lab_archive.ARCHIVE_MAGIC + bytes([ota_lab_archive.ARCHIVE_SCHEMA_VERSION]) + nonce +
                ota_lab_archive.struct.pack(">I", len(ciphertext)) + ciphertext)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "does not match its own declared"):
            ota_lab_archive.decrypt_archive(key, blob)

    def test_missing_required_metadata_field_is_rejected(self):
        key = os.urandom(32)
        metadata = self._full_metadata()
        del metadata["stable_serial"]
        blob = ota_lab_archive.encrypt_archive(key, metadata, b"abc", b"def")
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "stable_serial"):
            ota_lab_archive.decrypt_archive(key, blob)

    def _complete_full_metadata(self, **extra):
        # A genuinely complete, self-consistent, full-media-capture record --
        # i.e. exactly what cmd_archive() itself would produce -- so tests
        # below can introduce ONE specific, deliberate defect at a time and
        # prove decrypt_archive() catches it, rather than testing against an
        # already-incomplete baseline.
        region_table = ota_lab_archive.build_region_table()
        metadata = self._full_metadata(
            diagnostic_profile_id=ota_lab_archive.DIAGNOSTIC_PROFILE_ID,
            protocol_version=ota_lab_archive.PROTOCOL_VERSION,
            qspi_captured=True,
            qspi_jedec_hex="85:60:15",
            internal_full={"size": len(DEFAULT_INTERNAL), "sha256": ota_lab_archive.sha256_hex(DEFAULT_INTERNAL)},
            qspi_full={"size": len(DEFAULT_QSPI), "sha256": ota_lab_archive.sha256_hex(DEFAULT_QSPI)},
            regions=ota_lab_archive.region_hashes(region_table, DEFAULT_INTERNAL, DEFAULT_QSPI),
        )
        metadata.update(extra)
        return metadata

    def test_full_capture_with_missing_regions_dict_is_rejected_not_reported_ok(self):
        # A correctly AES-encrypted FULL media body paired with only
        # identity/length metadata (no 'regions' at all) must never decrypt
        # successfully -- a valid auth tag only proves who wrote the
        # container, never that its JSON actually describes the enclosed
        # bytes completely.
        key = os.urandom(32)
        metadata = self._complete_full_metadata()
        del metadata["regions"]
        blob = ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "regions"):
            ota_lab_archive.decrypt_archive(key, blob)

    def test_full_capture_missing_sdk28_region_entry_is_rejected(self):
        key = os.urandom(32)
        metadata = self._complete_full_metadata()
        del metadata["regions"]["internal_bootloader_settings_sdk28"]
        blob = ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "regions"):
            ota_lab_archive.decrypt_archive(key, blob)

    def test_full_capture_wrong_region_offset_is_rejected(self):
        key = os.urandom(32)
        metadata = self._complete_full_metadata()
        metadata["regions"]["qspi_candidate"]["offset"] += 4096
        blob = ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "qspi_candidate"):
            ota_lab_archive.decrypt_archive(key, blob)

    def test_full_capture_wrong_region_hash_is_rejected(self):
        key = os.urandom(32)
        metadata = self._complete_full_metadata()
        metadata["regions"]["internal_extrafs"]["sha256"] = "0" * 64
        blob = ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "internal_extrafs"):
            ota_lab_archive.decrypt_archive(key, blob)

    def test_full_capture_wrong_internal_full_claim_is_rejected(self):
        key = os.urandom(32)
        metadata = self._complete_full_metadata()
        metadata["internal_full"]["sha256"] = "0" * 64
        blob = ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "internal_full"):
            ota_lab_archive.decrypt_archive(key, blob)

    def test_full_capture_qspi_not_captured_true_is_rejected(self):
        key = os.urandom(32)
        metadata = self._complete_full_metadata(qspi_captured=False)
        blob = ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "QSPI capture"):
            ota_lab_archive.decrypt_archive(key, blob)

    def test_full_capture_wrong_diagnostic_profile_is_rejected(self):
        key = os.urandom(32)
        metadata = self._complete_full_metadata(diagnostic_profile_id=0xEE)
        blob = ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "diagnostic_profile_id"):
            ota_lab_archive.decrypt_archive(key, blob)

    def test_full_capture_malformed_jedec_hex_is_rejected(self):
        key = os.urandom(32)
        metadata = self._complete_full_metadata(qspi_jedec_hex="not-a-jedec-id")
        blob = ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "qspi_jedec_hex"):
            ota_lab_archive.decrypt_archive(key, blob)

    def test_full_capture_well_formed_but_wrong_jedec_id_is_rejected(self):
        # A genuinely valid, TEST-key-encrypted, FULL-media archive (real
        # auth tag, exact 1 MiB + 2 MiB bytes, otherwise-complete metadata)
        # that simply RELABELS its JEDEC ID as some other well-formed value
        # (e.g. "01:02:03") must be refused just as firmly as a malformed
        # one -- syntax alone (regex length/format) is never sufficient
        # evidence that the recorded part is the approved P25Q16H.
        key = os.urandom(32)
        metadata = self._complete_full_metadata(qspi_jedec_hex="01:02:03")
        blob = ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "qspi_jedec_hex.*01:02:03"):
            ota_lab_archive.decrypt_archive(key, blob)


class ArchiveAndVerifyCommandTests(ScratchDirMixin, unittest.TestCase):
    def _make_args(self, role, key_path, **extra):
        import argparse
        base = dict(role=role, key_file=str(key_path), timeout=1.0, retries=2, validate_only=False)
        base.update(extra)
        return argparse.Namespace(**base)

    @contextlib.contextmanager
    def _wired_device(self, device: FakeDevice, role="target", stable_serial=TARGET_SERIAL):
        by_id = pathlib.Path("/dev/serial/by-id/authorized-target")
        resolved_device = mock.Mock(serial=stable_serial, by_id=by_id)
        with mock.patch.object(ota_lab_archive, "resolve_authorized_device",
                               return_value=(resolved_device, stable_serial)), \
                mock.patch.object(ota_lab_archive, "open_serial_port", return_value=device):
            yield

    def test_archive_then_verify_round_trip_succeeds_on_unchanged_device(self):
        key_path = self.make_key_file()
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        archive_path = self.scratch / "target.archive"
        args = self._make_args("target", key_path, output=str(archive_path))
        with self._wired_device(device):
            self.assertEqual(0, ota_lab_archive.cmd_archive(args))
        self.assertTrue(archive_path.is_file())
        self.assertEqual(0o600, archive_path.stat().st_mode & 0o777)

        verify_args = self._make_args("target", key_path, archive=str(archive_path))
        device2 = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        with self._wired_device(device2):
            self.assertEqual(0, ota_lab_archive.cmd_verify(verify_args))

    def test_archive_metadata_includes_bootloader_settings_sdk28_region(self):
        # The full internal dump already contains these bytes; this test
        # confirms the named, canonical-address-sourced metadata entry for
        # them is actually produced and auto-covered by verify -- not that
        # a special/separate device read happened.
        key_path = self.make_key_file()
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        archive_path = self.scratch / "target.archive"
        args = self._make_args("target", key_path, output=str(archive_path))
        with self._wired_device(device):
            ota_lab_archive.cmd_archive(args)

        key = ota_lab_archive.load_key(key_path)
        metadata, internal_full, _qspi_full = ota_lab_archive.decrypt_archive(key, archive_path.read_bytes())
        entry = metadata["regions"]["internal_bootloader_settings_sdk28"]
        self.assertEqual(0x000FF000, entry["offset"])
        self.assertEqual(28, entry["size"])
        self.assertEqual("internal", entry["media"])
        expected = ota_lab_archive.sha256_hex(internal_full[0x000FF000:0x000FF000 + 28])
        self.assertEqual(expected, entry["sha256"])

    def test_verify_detects_a_tampered_bootloader_settings_sdk28_byte(self):
        key_path = self.make_key_file()
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        archive_path = self.scratch / "target.archive"
        args = self._make_args("target", key_path, output=str(archive_path))
        with self._wired_device(device):
            ota_lab_archive.cmd_archive(args)

        mutated_internal = bytearray(DEFAULT_INTERNAL)
        mutated_internal[0x000FF000] ^= 0xFF  # flip one byte inside the SDK28 settings window only.
        device2 = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL), internal_data=bytes(mutated_internal))
        verify_args = self._make_args("target", key_path, archive=str(archive_path))
        stderr = io.StringIO()
        with self._wired_device(device2):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaisesRegex(SystemExit, "difference"):
                    ota_lab_archive.cmd_verify(verify_args)
        self.assertIn("internal_bootloader_settings_sdk28", stderr.getvalue())

    def test_verify_reports_explicit_difference_and_offset(self):
        key_path = self.make_key_file()
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        archive_path = self.scratch / "target.archive"
        args = self._make_args("target", key_path, output=str(archive_path))
        with self._wired_device(device):
            ota_lab_archive.cmd_archive(args)

        mutated_internal = bytearray(DEFAULT_INTERNAL)
        mutated_internal[12345] ^= 0xFF
        device2 = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL), internal_data=bytes(mutated_internal))
        verify_args = self._make_args("target", key_path, archive=str(archive_path))
        with self._wired_device(device2):
            with self.assertRaisesRegex(SystemExit, "difference"):
                ota_lab_archive.cmd_verify(verify_args)

    def test_verify_refuses_mismatched_device_before_reading(self):
        key_path = self.make_key_file()
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        archive_path = self.scratch / "target.archive"
        args = self._make_args("target", key_path, output=str(archive_path))
        with self._wired_device(device):
            ota_lab_archive.cmd_archive(args)

        other_device = FakeDevice(uid=bytes.fromhex(CLIENT_SERIAL))
        other_device.refuse_all_reads = True
        verify_args = self._make_args("target", key_path, archive=str(archive_path))
        with self._wired_device(other_device, stable_serial=CLIENT_SERIAL):
            with self.assertRaisesRegex(SystemExit, "mismatched devices"):
                ota_lab_archive.cmd_verify(verify_args)

    def test_archive_refuses_incomplete_capture_when_qspi_not_ready(self):
        key_path = self.make_key_file()
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL), qspi_ok=False)
        archive_path = self.scratch / "target.archive"
        args = self._make_args("target", key_path, output=str(archive_path))
        with self._wired_device(device):
            with self.assertRaisesRegex(SystemExit, "QSPI not initialized"):
                ota_lab_archive.cmd_archive(args)
        self.assertFalse(archive_path.exists())

    def test_corrupted_archive_file_denied_by_verify(self):
        key_path = self.make_key_file()
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        archive_path = self.scratch / "target.archive"
        args = self._make_args("target", key_path, output=str(archive_path))
        with self._wired_device(device):
            ota_lab_archive.cmd_archive(args)

        raw = bytearray(archive_path.read_bytes())
        raw[-1] ^= 0xFF
        archive_path.write_bytes(bytes(raw))

        device2 = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device2.refuse_all_reads = True  # corruption must be caught before any device read.
        verify_args = self._make_args("target", key_path, archive=str(archive_path))
        with self._wired_device(device2):
            with self.assertRaises(ota_lab_archive.ProtocolError):
                ota_lab_archive.cmd_verify(verify_args)

    def test_archive_refuses_to_overwrite_an_existing_output_file(self):
        key_path = self.make_key_file()
        archive_path = self.scratch / "target.archive"
        archive_path.write_bytes(b"PRIOR-EVIDENCE-FILE")
        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        args = self._make_args("target", key_path, output=str(archive_path))
        with self._wired_device(device):
            with self.assertRaisesRegex(SystemExit, "refusing to overwrite"):
                ota_lab_archive.cmd_archive(args)
        # The prior file at that path must survive completely untouched.
        self.assertEqual(b"PRIOR-EVIDENCE-FILE", archive_path.read_bytes())

    def test_verify_refuses_a_partial_capture_archive_before_any_device_io(self):
        key_path = self.make_key_file()
        # Hand-build a "damaged"/hand-edited archive claiming a short,
        # non-full-media capture -- must be refused before any serial I/O.
        key = ota_lab_archive.load_key(key_path)
        metadata = {
            "schema": ota_lab_archive.ARCHIVE_SCHEMA_VERSION,
            "role": "target",
            "stable_serial": TARGET_SERIAL,
            "device_uid_hex": TARGET_SERIAL,
        }
        blob = ota_lab_archive.encrypt_archive(key, metadata, b"only-a-few-bytes", b"")
        archive_path = self.scratch / "partial.archive"
        archive_path.write_bytes(blob)

        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device.refuse_all_reads = True  # must never be reached.
        verify_args = self._make_args("target", key_path, archive=str(archive_path))
        with self._wired_device(device):
            with self.assertRaisesRegex(SystemExit, "not a full-media capture"):
                ota_lab_archive.cmd_verify(verify_args)

    def _full_valid_archive_bytes(self, key, **metadata_overrides):
        region_table = ota_lab_archive.build_region_table()
        metadata = {
            "schema": ota_lab_archive.ARCHIVE_SCHEMA_VERSION,
            "role": "target",
            "stable_serial": TARGET_SERIAL,
            "device_uid_hex": TARGET_SERIAL,
            "diagnostic_profile_id": ota_lab_archive.DIAGNOSTIC_PROFILE_ID,
            "protocol_version": ota_lab_archive.PROTOCOL_VERSION,
            "qspi_captured": True,
            "qspi_jedec_hex": "85:60:15",
            "internal_full": {"size": len(DEFAULT_INTERNAL), "sha256": ota_lab_archive.sha256_hex(DEFAULT_INTERNAL)},
            "qspi_full": {"size": len(DEFAULT_QSPI), "sha256": ota_lab_archive.sha256_hex(DEFAULT_QSPI)},
            "regions": ota_lab_archive.region_hashes(region_table, DEFAULT_INTERNAL, DEFAULT_QSPI),
        }
        metadata.update(metadata_overrides)
        return ota_lab_archive.encrypt_archive(key, metadata, DEFAULT_INTERNAL, DEFAULT_QSPI)

    def test_offline_validation_authenticates_full_capture_without_device_access(self):
        key_path = self.make_key_file()
        archive_path = self.scratch / "target.archive"
        archive_path.write_bytes(self._full_valid_archive_bytes(ota_lab_archive.load_key(key_path)))
        args = self._make_args("target", key_path, archive=str(archive_path), validate_only=True)
        output = io.StringIO()
        with mock.patch.object(lab_device, "resolve") as resolve_mock, \
                mock.patch.object(ota_lab_archive, "open_serial_port") as open_mock, \
                contextlib.redirect_stdout(output):
            self.assertEqual(0, ota_lab_archive.cmd_verify(args))
        resolve_mock.assert_not_called()
        open_mock.assert_not_called()
        self.assertIn("no live device comparison", output.getvalue())

    def test_offline_validation_refuses_wrong_role_serial_or_uid(self):
        key_path = self.make_key_file()
        key = ota_lab_archive.load_key(key_path)
        archive_path = self.scratch / "target.archive"
        args = self._make_args("target", key_path, archive=str(archive_path), validate_only=True)
        for field, value in (("role", "client"), ("stable_serial", CLIENT_SERIAL),
                             ("device_uid_hex", CLIENT_SERIAL)):
            with self.subTest(field=field):
                archive_path.write_bytes(self._full_valid_archive_bytes(key, **{field: value}))
                with self.assertRaisesRegex(ota_lab_archive.DeviceRefused, "does not match"):
                    ota_lab_archive.cmd_verify(args)

    def test_offline_validation_refuses_corruption_and_partial_capture(self):
        key_path = self.make_key_file()
        key = ota_lab_archive.load_key(key_path)
        archive_path = self.scratch / "target.archive"
        args = self._make_args("target", key_path, archive=str(archive_path), validate_only=True)
        damaged = bytearray(self._full_valid_archive_bytes(key))
        damaged[-1] ^= 1
        archive_path.write_bytes(damaged)
        with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "authentication failed"):
            ota_lab_archive.cmd_verify(args)
        metadata = {"schema": ota_lab_archive.ARCHIVE_SCHEMA_VERSION, "role": "target",
                    "stable_serial": TARGET_SERIAL, "device_uid_hex": TARGET_SERIAL}
        archive_path.write_bytes(ota_lab_archive.encrypt_archive(key, metadata, b"partial", b""))
        with self.assertRaisesRegex(SystemExit, "not a full-media capture"):
            ota_lab_archive.cmd_verify(args)

    def test_verify_refuses_same_uid_but_archive_role_reassigned_with_zero_media_reads(self):
        # Same physical device UID, but the archive was captured under a
        # DIFFERENT role name than what this invocation resolved (e.g.
        # lab/devices.ini's role<->serial mapping was reassigned since
        # capture) -- must refuse before any media dump, never report
        # "verify OK" under the new role.
        key_path = self.make_key_file()
        key = ota_lab_archive.load_key(key_path)
        blob = self._full_valid_archive_bytes(key, role="client")
        archive_path = self.scratch / "reassigned-role.archive"
        archive_path.write_bytes(blob)

        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device.refuse_all_reads = True  # full media dump must never be attempted.
        verify_args = self._make_args("target", key_path, archive=str(archive_path))
        with self._wired_device(device):
            with self.assertRaisesRegex(SystemExit, "reassigned/renamed role"):
                ota_lab_archive.cmd_verify(verify_args)

    def test_verify_refuses_same_uid_but_archive_stable_serial_reassigned_with_zero_media_reads(self):
        key_path = self.make_key_file()
        key = ota_lab_archive.load_key(key_path)
        blob = self._full_valid_archive_bytes(key, stable_serial=CLIENT_SERIAL)
        archive_path = self.scratch / "reassigned-serial.archive"
        archive_path.write_bytes(blob)

        device = FakeDevice(uid=bytes.fromhex(TARGET_SERIAL))
        device.refuse_all_reads = True  # full media dump must never be attempted.
        verify_args = self._make_args("target", key_path, archive=str(archive_path))
        with self._wired_device(device):
            with self.assertRaisesRegex(SystemExit, "reassigned role"):
                ota_lab_archive.cmd_verify(verify_args)

    def test_verify_refuses_well_formed_but_wrong_archived_jedec_before_any_device_io(self):
        # A genuinely valid, TEST-key-encrypted, FULL-media archive that
        # relabels its recorded JEDEC ID to some other well-formed value
        # must be refused entirely BEFORE this tool ever opens the serial
        # port or queries the live device -- decrypt_archive() itself must
        # catch this, not merely a later live-vs-archived comparison.
        key_path = self.make_key_file()
        key = ota_lab_archive.load_key(key_path)
        blob = self._full_valid_archive_bytes(key, qspi_jedec_hex="01:02:03")
        archive_path = self.scratch / "relabeled-jedec.archive"
        archive_path.write_bytes(blob)

        verify_args = self._make_args("target", key_path, archive=str(archive_path))
        with mock.patch.object(ota_lab_archive, "resolve_authorized_device") as resolve_mock, \
                mock.patch.object(ota_lab_archive, "open_serial_port") as open_mock:
            with self.assertRaisesRegex(ota_lab_archive.ProtocolError, "qspi_jedec_hex"):
                ota_lab_archive.cmd_verify(verify_args)
        resolve_mock.assert_not_called()  # zero device I/O of any kind, not just zero media reads.
        open_mock.assert_not_called()

    def test_no_restore_or_rollback_entry_point_exists(self):
        forbidden = ("cmd_restore", "restore", "rollback", "cmd_rollback", "cmd_reseed", "reseed")
        for name in forbidden:
            self.assertFalse(hasattr(ota_lab_archive, name), f"unexpected restore-capable entry point: {name}")


if __name__ == "__main__":
    unittest.main()
