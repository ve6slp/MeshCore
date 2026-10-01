import unittest
from dataclasses import replace
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import ota_maintenance_protocol as codec  # noqa: E402

# Independently specified wire literals; these exact bytes are also consumed
# by the native C++ product tests.
OPEN_REQUEST = bytes.fromhex(
    "42 20 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 02 03 04 "
    "00 00 00 00 00 00 00 00 10 00 00 00 00 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
)
CHALLENGE_REQUEST = bytes.fromhex(
    "42 29 01 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f "
    "01 02 03 04 11 22 33 44 04 00 00 00 00 00 00 00 00 00"
)
ACTIVATION_CHALLENGE_REQUEST = bytes.fromhex(
    "42 29 01 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f "
    "01 02 03 04 11 22 33 44 05 00 00 00 00 00 00 00 00 00"
)
READ_REPLY = bytes.fromhex(
    "1f 27 01 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f "
    "01 02 03 04 11 22 33 44 01 00 00 00 eb 00 00 00 05 03 aa bb cc"
)
CHALLENGE_REPLY = bytes.fromhex(
    "1f 29 01 00 00 01 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f "
    "01 02 03 04 11 22 33 44 00 00 00 00 00 00 00 00 00 10 "
    "80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
)
MEASUREMENT = bytes.fromhex(
    "01 01 02 03 04 05 06 07 08 "
    "10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f "
    "01 02 03 04 11 12 13 14 00 00 00 01 a1 a2 a3 a4 "
    "30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e 3f 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f "
    "00 00 12 34 00 02 70 00 "
    "50 51 52 53 54 55 56 57 58 59 5a 5b 5c 5d 5e 5f 60 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f "
    "be ef 00 00 10 00 00 00 20 00 "
    "70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f "
    "00 01 00 02 "
    "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f "
    "a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af "
    "d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb"
)


class MaintenanceProtocolTests(unittest.TestCase):
    def test_literal_open_request_round_trip(self):
        self.assertEqual(53, len(OPEN_REQUEST))
        decoded = codec.decode_request(OPEN_REQUEST)
        self.assertEqual(codec.Subcommand.OPEN, decoded.subcommand)
        self.assertEqual(0x01020304, decoded.request_id)
        self.assertEqual(bytes(range(16)), decoded.data)
        self.assertEqual(OPEN_REQUEST, codec.encode_request(decoded))

    def test_read_slice_count_is_header_only_request_data_len(self):
        request = codec.Request(
            subcommand=codec.Subcommand.READ_OBJECT,
            session=b"\x01" + bytes(15),
            request_id=0x01020304,
            object_kind=codec.ObjectKind.MEASUREMENT,
            total=235,
            offset=232,
            data_len=3,
        )
        wire = codec.encode_request(request)
        self.assertEqual(37, len(wire))
        decoded = codec.decode_request(wire)
        self.assertEqual(3, decoded.data_len)
        self.assertEqual(b"", decoded.data)
        matching_reply = codec.decode_reply(READ_REPLY)
        self.assertEqual(decoded.request_id, matching_reply.request_id)
        self.assertEqual(decoded.data_len, len(matching_reply.data))
        with self.assertRaises(codec.RangeOutOfBoundsError):
            codec.encode_request(
                codec.Request(
                    subcommand=codec.Subcommand.READ_OBJECT,
                    session=b"\x01" + bytes(15),
                    request_id=0x01020304,
                    object_kind=codec.ObjectKind.MEASUREMENT,
                    total=235,
                    offset=233,
                    data_len=3,
                )
            )

    def test_literal_reply_round_trip_and_big_endian_fields(self):
        self.assertEqual(43, len(READ_REPLY))
        reply = codec.decode_reply(READ_REPLY)
        self.assertEqual(codec.Status.OK, reply.status)
        self.assertEqual(codec.Reason.NONE, reply.reason)
        self.assertEqual(0x01020304, reply.request_id)
        self.assertEqual(0x11223344, reply.job_ticket)
        self.assertEqual(READ_REPLY, codec.encode_reply(reply))

    def test_literal_235_byte_measurement_round_trip(self):
        self.assertEqual(235, len(MEASUREMENT))
        measured = codec.decode_measurement(MEASUREMENT)
        self.assertEqual(1, measured.current_role)
        self.assertEqual(0x00010002, measured.boot_config_id)
        self.assertEqual(bytes(range(0xD0, 0xEC)), measured.raw_sdk28)
        self.assertEqual(MEASUREMENT, codec.encode_measurement(measured))

    def test_tamper_controls(self):
        cases = (
            (OPEN_REQUEST[:36], codec.TruncatedFrameError),
            (OPEN_REQUEST[:-1], codec.DataLengthMismatchError),
            (OPEN_REQUEST + b"\x00", codec.DataLengthMismatchError),
        )
        for frame, error in cases:
            with self.subTest(error=error.__name__), self.assertRaises(error):
                codec.decode_request(frame)
        altered = bytearray(OPEN_REQUEST)
        altered[2] = 2
        with self.assertRaises(codec.UnsupportedVersionError):
            codec.decode_request(bytes(altered))
        altered = bytearray(OPEN_REQUEST)
        altered[1] = 0x2B
        with self.assertRaises(codec.UnsupportedSubcommandError):
            codec.decode_request(bytes(altered))
        altered = bytearray(OPEN_REQUEST)
        altered[27] = 11
        with self.assertRaises(codec.UnsupportedObjectKindError):
            codec.decode_request(bytes(altered))
        altered = bytearray(READ_REPLY)
        altered[3] = 0xFF
        with self.assertRaises(codec.UnsupportedStatusError):
            codec.decode_reply(bytes(altered))
        altered = bytearray(READ_REPLY)
        altered[4:6] = b"\x12\x34"
        opaque_reason = codec.decode_reply(bytes(altered))
        self.assertEqual(0x1234, opaque_reason.reason)
        self.assertEqual(bytes(altered), codec.encode_reply(opaque_reason))
        altered = bytearray(READ_REPLY)
        altered[39] = 2
        with self.assertRaises(codec.DataLengthMismatchError):
            codec.decode_reply(bytes(altered))
        altered = bytearray(READ_REPLY)
        altered[33:37] = b"\x00\x00\x00\xea"
        with self.assertRaises(codec.InvalidObjectLengthError):
            codec.decode_reply(bytes(altered))
        with self.assertRaises(codec.ExtraFrameBytesError):
            codec.decode_measurement(MEASUREMENT + b"\x00")
        altered = bytearray(MEASUREMENT)
        altered[0] = 2
        with self.assertRaises(codec.InvalidMeasurementVersionError):
            codec.decode_measurement(bytes(altered))

    def test_fragment_bounds_and_session_request_ids(self):
        base = dict(
            subcommand=codec.Subcommand.PUT_FRAGMENT,
            session=b"\x01" + bytes(15),
            request_id=7,
            object_kind=codec.ObjectKind.PREPARED_ARTIFACT,
            total=683,
            offset=680,
            data_len=4,
            data=b"abcd",
        )
        with self.assertRaises(codec.RangeOutOfBoundsError):
            codec.encode_request(codec.Request(**base))
        base.update(offset=0xFFFFFFF0, data_len=32, data=b"x" * 32)
        with self.assertRaises(codec.RangeOverflowError):
            codec.encode_request(codec.Request(**base))
        base.update(offset=0, data_len=4, data=b"abcd", session=bytes(16))
        with self.assertRaises(codec.InvalidSessionError):
            codec.encode_request(codec.Request(**base))
        base.update(session=b"\x01" + bytes(15), request_id=0)
        with self.assertRaises(codec.InvalidRequestIdError):
            codec.encode_request(codec.Request(**base))

    def test_128_byte_slice_boundary_and_oversize(self):
        data = bytes(128)
        request = codec.Request(
            subcommand=codec.Subcommand.PUT_FRAGMENT,
            session=b"\x01" + bytes(15),
            request_id=1,
            object_kind=codec.ObjectKind.PREPARED_ARTIFACT,
            total=683,
            offset=0,
            data_len=128,
            data=data,
        )
        wire = codec.encode_request(request)
        self.assertEqual(165, len(wire))
        self.assertEqual(data, codec.decode_request(wire).data)
        with self.assertRaises(codec.DataTooLargeError):
            codec.encode_request(
                codec.Request(
                    subcommand=codec.Subcommand.READ_OBJECT,
                    session=b"\x01" + bytes(15),
                    request_id=2,
                    object_kind=codec.ObjectKind.PREPARED_ARTIFACT,
                    total=683,
                    offset=0,
                    data_len=129,
                )
            )

    def test_all_subcommands_statuses_and_object_kinds(self):
        header_only = (
            codec.Subcommand.MEASURE,
            codec.Subcommand.CERTIFY,
            codec.Subcommand.PREPARE,
            codec.Subcommand.ACTIVATE,
            codec.Subcommand.POLL,
            codec.Subcommand.CANCEL,
            codec.Subcommand.CLOSE,
        )
        for sub in header_only:
            with self.subTest(subcommand=sub):
                req = codec.Request(
                    subcommand=sub, session=b"\x01" + bytes(15), request_id=int(sub)
                )
                self.assertEqual(req, codec.decode_request(codec.encode_request(req)))

        for kind, total in codec.OBJECT_LENGTHS.items():
            if kind == codec.ObjectKind.NONE:
                continue
            with self.subTest(object_kind=kind):
                req = codec.Request(
                    subcommand=codec.Subcommand.PUT_FRAGMENT,
                    session=b"\x01" + bytes(15),
                    request_id=int(kind),
                    object_kind=kind,
                    total=total,
                    offset=0,
                    data_len=1,
                    data=bytes((int(kind),)),
                )
                self.assertEqual(req, codec.decode_request(codec.encode_request(req)))

        for status in codec.Status:
            with self.subTest(status=status):
                reply = codec.Reply(
                    subcommand=codec.Subcommand.POLL,
                    status=status,
                    request_id=1,
                    reason=codec.Reason.NO_BACKEND_BOUND,
                )
                decoded = codec.decode_reply(codec.encode_reply(reply))
                self.assertEqual(status, decoded.status)
                self.assertEqual(codec.Reason.NO_BACKEND_BOUND, decoded.reason)

    def test_challenge_request_golden_vector_requires_ticket_and_purpose_kind(self):
        self.assertEqual(37, len(CHALLENGE_REQUEST))
        challenge = codec.decode_request(CHALLENGE_REQUEST)
        self.assertEqual(codec.Subcommand.CHALLENGE, challenge.subcommand)
        self.assertEqual(codec.ObjectKind.PREPARE_AUTHORIZATION, challenge.object_kind)
        self.assertEqual(0x11223344, challenge.job_ticket)
        self.assertEqual(b"", challenge.data)
        self.assertEqual(CHALLENGE_REQUEST, codec.encode_request(challenge))

        activation = codec.decode_request(ACTIVATION_CHALLENGE_REQUEST)
        self.assertEqual(
            codec.ObjectKind.ACTIVATION_AUTHORIZATION, activation.object_kind
        )
        self.assertEqual(ACTIVATION_CHALLENGE_REQUEST, codec.encode_request(activation))
        invalid_changes = (
            {"object_kind": codec.ObjectKind.NONE},
            {"object_kind": codec.ObjectKind.MEASUREMENT},
            {"job_ticket": 0},
            {"total": 267},
            {"offset": 1},
            {"data_len": 1, "data": b"x"},
        )
        for changes in invalid_changes:
            with (
                self.subTest(changes=changes),
                self.assertRaises(codec.InvalidOperationShapeError),
            ):
                codec.encode_request(replace(challenge, **changes))

    def test_challenge_success_refusal_and_opaque_reason_round_trip(self):
        challenge = codec.decode_reply(CHALLENGE_REPLY)
        self.assertEqual(codec.Subcommand.CHALLENGE, challenge.subcommand)
        self.assertEqual(codec.Status.OK, challenge.status)
        self.assertEqual(bytes(range(0x80, 0x90)), challenge.data)
        self.assertEqual(CHALLENGE_REPLY, codec.encode_reply(challenge))

        denied = codec.Reply(
            subcommand=codec.Subcommand.CHALLENGE,
            status=codec.Status.DENIED,
            reason=codec.Reason.NO_SESSION,
            request_id=0x01020304,
        )
        denied_wire = codec.encode_reply(denied)
        self.assertEqual(codec.Status.DENIED, codec.decode_reply(denied_wire).status)
        with self.assertRaises(codec.DataLengthMismatchError):
            codec.decode_reply(CHALLENGE_REPLY[:-1])

        opaque = bytearray(READ_REPLY)
        opaque[4:6] = b"\xca\xfe"
        decoded = codec.decode_reply(bytes(opaque))
        self.assertEqual(0xCAFE, decoded.reason)
        self.assertEqual(bytes(opaque), codec.encode_reply(decoded))

    def test_measurement_role_and_config_are_structural_constraints(self):
        decoded = codec.decode_measurement(MEASUREMENT)
        decoded.current_role = 2
        with self.assertRaises(codec.InvalidMeasurementRoleError):
            codec.encode_measurement(decoded)
        decoded = codec.decode_measurement(MEASUREMENT)
        decoded.boot_config_id = 1
        with self.assertRaises(codec.InvalidBootConfigIdError):
            codec.encode_measurement(decoded)


if __name__ == "__main__":
    unittest.main()
