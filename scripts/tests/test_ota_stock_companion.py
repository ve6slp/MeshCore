import struct
from types import SimpleNamespace
import unittest

from test_ota_uploader import ADMIN, ADMIN_PRIVATE, canonical
from ota_common import Error, Frame, Kind, sign
from ota_compression import Package
from ota_stock_companion import StockTransport
from ota_transport import NativeTransport, Route


class Clock:
    def __init__(self):
        self.now = 1.0

    def __call__(self):
        return self.now

    def sleep(self, value):
        self.now += value


class StockNode:
    def __init__(self):
        self.commands, self.pending = [], []
        self.sent = self.direct = 0
        self.complete = True

    def command(self, body, **_):
        self.commands.append(body)
        if body[:1] == b"\x41":
            if self.complete:
                self.sent += 1
                self.direct += body[2] == 0x32
            return b"\0"
        if body == b"\x38\x00":
            return b"\x18\x00" + bytes(9)
        if body == b"\x38\x01":
            return b"\x18\x01" + bytes(12)
        if body == b"\x38\x02":
            return b"\x18\x02" + struct.pack("<IIIIIII", 0, self.sent, 0, self.direct, 0, 0, 0)
        raise AssertionError("unexpected or forbidden stock command")


class TransportTests(unittest.TestCase):
    def frame(self):
        return Frame(Kind.DATA, 1, b"P" * 8, 0, 8192, 0, bytes(128)).encode()

    def test_stock_tx_requires_physical_counter_not_queue_admission(self):
        clock, node = Clock(), StockNode()
        transport = StockTransport(node, ADMIN, Route(), clock=clock, sleep=clock.sleep)
        transport.profile = (918000, 62500, 7, 5, 1)
        receipt = transport.send(self.frame(), 10)
        self.assertGreater(receipt.airtime, 0)
        self.assertEqual(receipt.wire_bytes, 153)
        self.assertTrue(all(command[0] in (56, 65) for command in node.commands))
        node.complete = False
        with self.assertRaisesRegex(TimeoutError, "physical TX"):
            transport.send(self.frame(), 20)
        self.assertIsNotNone(transport.pending_tx)
        with self.assertRaisesRegex(Error, "never changed"):
            transport.cleanup(25)
        with self.assertRaisesRegex(Error, "CMD11"):
            transport.acquire_lease(None)

    def test_fixed_slices_reject_oversize_grown_path_and_do_not_add_retry_wrapper(self):
        self.assertEqual(len(Route(path=bytes(20), max_path_bytes=20).packet(self.frame())) + 3, 176)
        with self.assertRaises(ValueError):
            Route(path=bytes(21), max_path_bytes=21).packet(self.frame())
        self.assertEqual(Route().packet(self.frame())[2:4], b"\xd4\x05")

    def test_native_local_and_physical_bridge_preserve_exact_frame(self):
        clock = Clock()
        node = SimpleNamespace(pending=[], stream=SimpleNamespace(write_timeout=0))
        node.poll = lambda *_: None
        commands = []

        def write(body):
            commands.append(body)
            op = body[2]
            reply = bytes([30, 4, op, 0]) + (struct.pack(">I", 12345) if op == 1 else b"")
            node.pending.append((clock(), reply))
            if op == 2:
                node.pending.append((clock(), bytes([30, 4, 3]) + self.frame()))
        node.write_frame = write
        physical = NativeTransport(node, ADMIN, Route(), clock=clock)
        receipt = physical.send(self.frame(), 10)
        self.assertEqual(commands[-1], bytes([67, 4, 1]) + Route().packet(self.frame()))
        self.assertEqual(receipt.airtime, .012345)
        local = NativeTransport(node, ADMIN, Route(), local=True, clock=clock)
        self.assertEqual(local.send(self.frame(), 10).airtime, 0)
        self.assertEqual(commands[-1], bytes([67, 4, 2]) + self.frame())
        self.assertEqual(local.receive(10), self.frame())

    def test_signing_checks_advertised_buffer_before_uploading_any_data(self):
        calls = []
        def command(body, **_):
            calls.append(body)
            return b"\x13\0" + struct.pack("<I", 512)
        with self.assertRaisesRegex(Error, "buffer too small"):
            sign(SimpleNamespace(command=command), bytes(3000), ADMIN, 10**12)
        self.assertEqual(calls, [b"\x21"])

    def test_stock_8192_buffer_signs_full_maximum_manifest_once_not_data_frames(self):
        buffer, messages, serial_sizes = bytearray(), [], []

        def command(body, **_):
            serial_sizes.append(len(body))
            if body == b"\x21":
                buffer.clear()
                return b"\x13\0" + struct.pack("<I", 8192)
            if body[0] == 34:
                buffer.extend(body[1:])
                return b"\0"
            self.assertEqual(body, b"\x23")
            messages.append(bytes(buffer))
            return b"\x14" + ADMIN_PRIVATE.sign(bytes(buffer))

        node = SimpleNamespace(command=command)
        image = b"a" * (8192 * 128)
        pkg = Package.build(image, canonical(image), ADMIN,
                            lambda message: sign(node, message, ADMIN, 10**12))
        from ota_common import domain
        self.assertEqual(messages, [pkg.canonical, domain("package") + pkg.manifest[:-64]])
        self.assertEqual(len(pkg.manifest), 4707)
        self.assertLessEqual(max(serial_sizes), 176)


if __name__ == "__main__":
    unittest.main()
