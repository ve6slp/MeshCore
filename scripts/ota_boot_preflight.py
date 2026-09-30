#!/usr/bin/env python3

import argparse
import hashlib
import struct
import sys
from pathlib import Path

import lab_device
import ota_rf_lab


SECTOR_BYTES = 4096
READ_BYTES = 128
RESP_JOURNAL_DATA = 30
ERASE_CONFIRM_TOKEN = 0x464C4145
JOURNAL_SECTORS = (
    ("floor-a", 0x192000),
    ("floor-b", 0x193000),
    ("command-a", 0x18C000),
    ("command-b", 0x18D000),
    ("state-a", 0x18E000),
    ("state-b", 0x18F000),
    ("confirmation-a", 0x190000),
    ("confirmation-b", 0x191000),
)
ERASED_SECTOR = bytes([0xFF]) * SECTOR_BYTES
LEGACY_FLOOR_A = (
    bytes([0xFF]) * 3
    + bytes((0xE7 ^ (index * 11)) & 0xFF for index in range(37))
    + bytes([0xFF]) * (SECTOR_BYTES - 40)
)


class PreflightError(ValueError):
    pass


def classify_snapshot(snapshot):
    expected_names = {name for name, _ in JOURNAL_SECTORS}
    if set(snapshot) != expected_names:
        raise PreflightError("incomplete boot-journal snapshot")
    for name, data in snapshot.items():
        if len(data) != SECTOR_BYTES:
            raise PreflightError(f"{name}: expected a complete {SECTOR_BYTES}-byte sector")
        if name != "floor-a" and data != ERASED_SECTOR:
            raise PreflightError(f"{name}: existing metadata or transaction; refusing cleanup")
    if snapshot["floor-a"] == ERASED_SECTOR:
        return "blank"
    if snapshot["floor-a"] == LEGACY_FLOOR_A:
        return "historical-lab-residue"
    raise PreflightError("floor-a: existing or unknown metadata; refusing cleanup")


def read_sector(node, index):
    data = bytearray()
    for offset in range(0, SECTOR_BYTES, READ_BYTES):
        request = bytes([ota_rf_lab.CMD_OTA_LAB, 1, index]) + struct.pack(">H", offset) + bytes([READ_BYTES])
        reply = node.command(request, expected=(RESP_JOURNAL_DATA, ota_rf_lab.RESP_ERR))
        expected_header = bytes([RESP_JOURNAL_DATA, index]) + struct.pack(">H", offset) + bytes([READ_BYTES])
        if len(reply) != len(expected_header) + READ_BYTES or reply[:5] != expected_header:
            raise PreflightError(f"sector {index} offset {offset}: invalid read reply {reply.hex()}")
        data.extend(reply[5:])
    return bytes(data)


def archive_snapshot(node, evidence, label):
    directory = evidence.directory / label
    directory.mkdir()
    snapshot = {}
    for index, (name, address) in enumerate(JOURNAL_SECTORS):
        data = read_sector(node, index)
        (directory / f"{name}.bin").write_bytes(data)
        snapshot[name] = data
        evidence.log("journal-sector", phase=label, sector=name, address=address,
                     size=len(data), sha256=hashlib.sha256(data).hexdigest())
    return snapshot


def inspect_target(node, evidence, erase_known_residue=False):
    first = archive_snapshot(node, evidence, "before-read-1")
    second = archive_snapshot(node, evidence, "before-read-2")
    evidence.check("journal-reads-identical", first == second)
    classification = classify_snapshot(first)
    evidence.summary["measurements"]["floor_classification"] = classification
    evidence.check("legacy-commissioning-preflight", True, classification=classification,
                   journal_transactions_blank=True, bootloader_qualification="not-evaluated")
    if not erase_known_residue or classification == "blank":
        evidence.log("cleanup-not-performed", explicit_approval=erase_known_residue,
                     classification=classification)
        return classification

    immediate = archive_snapshot(node, evidence, "immediate-pre-erase")
    evidence.check("journal-unchanged-before-erase", immediate == first)
    classify_snapshot(immediate)
    request = bytes([ota_rf_lab.CMD_OTA_LAB, 2]) + struct.pack(">I", ERASE_CONFIRM_TOKEN)
    response = node.command(request)
    if response != bytes([ota_rf_lab.RESP_OK]):
        raise PreflightError(f"floor-a cleanup refused or failed: {response.hex()}")

    after = archive_snapshot(node, evidence, "after-read-1")
    after_again = archive_snapshot(node, evidence, "after-read-2")
    evidence.check("post-cleanup-reads-identical", after == after_again)
    disposition = classify_snapshot(after)
    untouched = all(after[name] == first[name] for name, _ in JOURNAL_SECTORS if name != "floor-a")
    evidence.check("single-floor-sector-cleaned", disposition == "blank" and untouched,
                   untouched_sectors_unchanged=untouched)
    evidence.summary["measurements"]["floor_classification_after_cleanup"] = disposition
    return disposition


def main():
    parser = argparse.ArgumentParser(description="Archive and inspect the authorized target's boot journal.")
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--erase-known-residue", action="store_true",
                        help="explicitly approve clearing only the exact historical floor-A lab residue")
    args = parser.parse_args()
    args.artifact_dir.mkdir(parents=True, exist_ok=False)
    evidence = ota_rf_lab.Evidence(args.artifact_dir)
    node = None
    error = None
    try:
        device = lab_device.resolve(ota_rf_lab.TARGET_ROLE, lab_device.MODE_APP)
        evidence.summary["measurements"]["device"] = {
            "role": ota_rf_lab.TARGET_ROLE, "serial": device.serial, "by_id": str(device.by_id),
        }
        node = ota_rf_lab.FramedSerial(f"target-{device.serial}", str(device.by_id), evidence)
        device_info = node.command(
            bytes([ota_rf_lab.CMD_DEVICE_QUERY, 13]),
            expected=(ota_rf_lab.RESP_DEVICE_INFO, ota_rf_lab.RESP_ERR))
        if len(device_info) < 2 or device_info[0] != ota_rf_lab.RESP_DEVICE_INFO:
            raise PreflightError(f"device identity query failed: {device_info.hex()}")
        evidence.summary["measurements"]["device"]["firmware_info_frame"] = device_info.hex()
        evidence.summary["measurements"]["application"] = ota_rf_lab.serializable_app_info(
            ota_rf_lab.app_info(node))
        inspect_target(node, evidence, args.erase_known_residue)
    finally:
        failure = sys.exc_info()[1]
        if failure is not None:
            error = f"{type(failure).__name__}: {failure}"
            evidence.log("fatal", error=error)
        if node is not None:
            node.close()
        evidence.finish(error)


if __name__ == "__main__":
    main()
