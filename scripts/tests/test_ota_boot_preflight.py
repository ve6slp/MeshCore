import pathlib
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import ota_boot_preflight as preflight
import ota_rf_lab


def blank_snapshot():
    return {name: preflight.ERASED_SECTOR for name, _ in preflight.JOURNAL_SECTORS}


class LegacyResidueTests(unittest.TestCase):
    def test_only_exact_historical_full_sector_pattern_qualifies(self):
        snapshot = blank_snapshot()
        self.assertEqual(preflight.classify_snapshot(snapshot), "blank")
        snapshot["floor-a"] = preflight.LEGACY_FLOOR_A
        self.assertEqual(snapshot["floor-a"][3:10], bytes.fromhex("e7ecf1c6cbd0a5"))
        self.assertEqual(preflight.classify_snapshot(snapshot), "historical-lab-residue")
        for offset in (0, 3, 39, 40, 4095):
            damaged = bytearray(preflight.LEGACY_FLOOR_A)
            damaged[offset] ^= 1
            snapshot["floor-a"] = bytes(damaged)
            with self.subTest(offset=offset), self.assertRaises(preflight.PreflightError):
                preflight.classify_snapshot(snapshot)

    def test_every_other_journal_sector_must_be_blank(self):
        for name, _ in preflight.JOURNAL_SECTORS[1:]:
            snapshot = blank_snapshot()
            snapshot["floor-a"] = preflight.LEGACY_FLOOR_A
            snapshot[name] = bytes([0]) + preflight.ERASED_SECTOR[1:]
            with self.subTest(sector=name), self.assertRaises(preflight.PreflightError):
                preflight.classify_snapshot(snapshot)

    def test_partial_or_incomplete_snapshots_are_rejected(self):
        snapshot = blank_snapshot()
        snapshot["floor-a"] = preflight.ERASED_SECTOR[:40]
        with self.assertRaises(preflight.PreflightError):
            preflight.classify_snapshot(snapshot)
        del snapshot["floor-a"]
        with self.assertRaises(preflight.PreflightError):
            preflight.classify_snapshot(snapshot)


class JournalReadTests(unittest.TestCase):
    def test_reads_complete_sector_with_exact_big_endian_reply_binding(self):
        node = mock.Mock()

        def reply(request, **kwargs):
            self.assertEqual(request[:3], bytes([ota_rf_lab.CMD_OTA_LAB, 1, 7]))
            self.assertEqual(request[5], 128)
            offset = struct.unpack(">H", request[3:5])[0]
            return bytes([30]) + request[2:] + bytes([offset // 128]) * 128

        node.command.side_effect = reply
        data = preflight.read_sector(node, 7)
        self.assertEqual(node.command.call_count, 32)
        self.assertEqual(data[:128], bytes(128))
        self.assertEqual(data[-128:], bytes([31]) * 128)

    def test_wrong_sector_offset_length_or_error_reply_is_rejected(self):
        expected = bytes.fromhex("1e00000080") + bytes(128)
        replies = [b"\x01\x06", expected[:-1], expected[:1] + b"\x01" + expected[2:],
                   expected[:2] + b"\x00\x80" + expected[4:],
                   expected[:4] + b"\x7f" + expected[5:]]
        for reply in replies:
            node = mock.Mock()
            node.command.return_value = reply
            with self.subTest(reply=reply[:5]), self.assertRaises(preflight.PreflightError):
                preflight.read_sector(node, 0)

    def test_inspection_archives_both_complete_read_passes_without_writing_flash(self):
        snapshot = blank_snapshot()
        snapshot["floor-a"] = preflight.LEGACY_FLOOR_A
        node = mock.Mock()

        def reply(request, **kwargs):
            self.assertEqual(request[:2], bytes([ota_rf_lab.CMD_OTA_LAB, 1]))
            index = request[2]
            offset = struct.unpack(">H", request[3:5])[0]
            name = preflight.JOURNAL_SECTORS[index][0]
            return bytes([30]) + request[2:] + snapshot[name][offset:offset + 128]

        node.command.side_effect = reply
        evidence = mock.Mock()
        evidence.summary = {"measurements": {}}
        root = pathlib.Path(__file__).resolve().parents[2] / ".tmp"
        root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as directory:
            evidence.directory = pathlib.Path(directory)
            self.assertEqual(preflight.inspect_target(node, evidence), "historical-lab-residue")
            for phase in ("before-read-1", "before-read-2"):
                for name, _ in preflight.JOURNAL_SECTORS:
                    self.assertEqual((evidence.directory / phase / f"{name}.bin").read_bytes(), snapshot[name])
        self.assertEqual(node.command.call_count, 512)
        evidence.check.assert_any_call(
            "legacy-commissioning-preflight", True, classification="historical-lab-residue",
            journal_transactions_blank=True, bootloader_qualification="not-evaluated")


class CleanupApprovalTests(unittest.TestCase):
    def run_fixture(self, snapshots, approved=False, erase_response=b"\x00"):
        root = pathlib.Path(__file__).resolve().parents[2] / ".tmp"
        root.mkdir(exist_ok=True)
        node = mock.Mock()
        self.last_node = node
        node.command.return_value = erase_response
        evidence = mock.Mock()
        evidence.summary = {"measurements": {}}

        def check(name, passed, **details):
            if not passed:
                raise AssertionError(name)

        evidence.check.side_effect = check
        with tempfile.TemporaryDirectory(dir=root) as directory:
            evidence.directory = pathlib.Path(directory)
            with mock.patch.object(preflight, "archive_snapshot", side_effect=snapshots):
                result = preflight.inspect_target(node, evidence, approved)
        return result, node

    def test_read_only_default_never_erases_known_residue(self):
        snapshot = blank_snapshot()
        snapshot["floor-a"] = preflight.LEGACY_FLOOR_A
        result, node = self.run_fixture([snapshot, snapshot])
        self.assertEqual(result, "historical-lab-residue")
        node.command.assert_not_called()

    def test_blank_journal_is_never_erased_even_when_approved(self):
        snapshot = blank_snapshot()
        result, node = self.run_fixture([snapshot, snapshot], approved=True)
        self.assertEqual(result, "blank")
        node.command.assert_not_called()

    def test_explicit_cleanup_rechecks_before_erase_and_verifies_after(self):
        snapshot = blank_snapshot()
        snapshot["floor-a"] = preflight.LEGACY_FLOOR_A
        after = blank_snapshot()
        result, node = self.run_fixture([snapshot, snapshot, snapshot, after, after], approved=True)
        self.assertEqual(result, "blank")
        node.command.assert_called_once_with(
            bytes([ota_rf_lab.CMD_OTA_LAB, 2]) + bytes.fromhex("464c4145"))

    def test_changed_journal_is_not_erased(self):
        snapshot = blank_snapshot()
        snapshot["floor-a"] = preflight.LEGACY_FLOOR_A
        after = blank_snapshot()
        with self.assertRaisesRegex(AssertionError, "journal-reads-identical"):
            self.run_fixture([snapshot, after], approved=True)
        self.last_node.command.assert_not_called()
        with self.assertRaisesRegex(AssertionError, "journal-unchanged-before-erase"):
            self.run_fixture([snapshot, snapshot, after], approved=True)
        self.last_node.command.assert_not_called()

    def test_unknown_floor_or_existing_transaction_is_never_erased(self):
        for name, _ in preflight.JOURNAL_SECTORS:
            snapshot = blank_snapshot()
            snapshot["floor-a"] = preflight.LEGACY_FLOOR_A
            snapshot[name] = bytes([0]) + preflight.ERASED_SECTOR[1:]
            with self.subTest(sector=name), self.assertRaises(preflight.PreflightError):
                self.run_fixture([snapshot, snapshot], approved=True)
            self.last_node.command.assert_not_called()

    def test_backend_refusal_and_failed_readback_are_not_success(self):
        snapshot = blank_snapshot()
        snapshot["floor-a"] = preflight.LEGACY_FLOOR_A
        with self.assertRaisesRegex(preflight.PreflightError, "refused or failed"):
            self.run_fixture([snapshot, snapshot, snapshot], approved=True, erase_response=b"\x01\x06")
        with self.assertRaisesRegex(AssertionError, "single-floor-sector-cleaned"):
            self.run_fixture([snapshot] * 5, approved=True)


if __name__ == "__main__":
    unittest.main()
