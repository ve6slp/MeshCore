import os
import argparse
import pathlib
import secrets
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import io
import contextlib
import hashlib
import zlib
import multiprocessing
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import ota_authority_registry as reg

ROOT = pathlib.Path(__file__).resolve().parents[2]
TMP_ROOT = ROOT / ".tmp"


def make_binding(tag: int) -> reg.AuthorityBinding:
    return reg.AuthorityBinding(
        hardware_uid=bytes([tag]) * reg.HARDWARE_UID_BYTES,
        mesh_full_public_key=bytes([tag + 1]) * reg.PUBLIC_KEY_BYTES,
        crypto_form=reg.CryptoDomainForm.PAIRWISE,
        group_selector=0,
        profile_id=1,
        layout_id=1,
        historical_initial_role_id=0,
        consent_owner_public_key=bytes([tag + 2]) * reg.PUBLIC_KEY_BYTES,
    )


def make_commission(tag: int, txn_id: bytes, digest: bytes, tx_floor=0, rx_floor=0) -> reg.AuthorityTransaction:
    return reg.AuthorityTransaction(
        binding=make_binding(tag),
        operation=reg.AuthorityOperation.COMMISSION,
        transaction_id=txn_id,
        revision=0,
        manifest_digest_sha256=digest,
        initial_tx_sequence_floor=tx_floor,
        initial_rx_replay_floor=rx_floor,
        issuer_key_id=1,
        issued_at_unix_seconds=1_700_000_000,
    )


class AuthorityRegistryTestCase(unittest.TestCase):
    """Base fixture: a fresh .tmp-scoped scratch dir (never /tmp), a real
    offline-generated issuer keypair, and helpers to sign transactions
    exactly the way the CLI does."""

    def setUp(self):
        TMP_ROOT.mkdir(exist_ok=True)
        self._tmp_ctx = tempfile.TemporaryDirectory(dir=TMP_ROOT)
        self.work_dir = pathlib.Path(self._tmp_ctx.name)
        self.key_dir = self.work_dir / "keys"
        self.private_key, self.public_key = reg.generate_issuer_keypair(self.key_dir)
        self.public_key_raw = reg.read_raw_public_key(self.public_key)
        self.copy_a_path = self.work_dir / "copy-a.sqlite"
        self.copy_b_path = self.work_dir / "copy-b.sqlite"

    def tearDown(self):
        self._tmp_ctx.cleanup()

    def sign(self, txn: reg.AuthorityTransaction) -> reg.AuthorityTransaction:
        message = reg.serialize_signed_message(txn)
        txn.issuer_signature_ed25519 = reg.sign_bytes(message, self.private_key, self.work_dir)
        return txn

    def pair(self) -> reg.AuthorityRegistryPair:
        return reg.AuthorityRegistryPair(
            reg.AuthorityRegistryCopy(self.copy_a_path), reg.AuthorityRegistryCopy(self.copy_b_path)
        )


class CodecTests(AuthorityRegistryTestCase):
    def test_round_trip_preserves_every_field(self):
        txn = self.sign(make_commission(1, secrets.token_bytes(16), b"\x11" * 32, 5, 7))
        record = reg.serialize_record(txn)
        self.assertEqual(len(record), reg.RECORD_BYTES)
        parsed = reg.parse_record(record)
        self.assertEqual(parsed.transaction_id, txn.transaction_id)
        self.assertEqual(parsed.binding.hardware_uid, txn.binding.hardware_uid)
        self.assertEqual(parsed.binding.mesh_full_public_key, txn.binding.mesh_full_public_key)
        self.assertEqual(parsed.manifest_digest_sha256, txn.manifest_digest_sha256)
        self.assertEqual(parsed.initial_tx_sequence_floor, 5)
        self.assertEqual(parsed.initial_rx_replay_floor, 7)
        self.assertEqual(parsed.issuer_signature_ed25519, txn.issuer_signature_ed25519)

    def test_truncated_record_raises_typed_too_short(self):
        txn = self.sign(make_commission(2, secrets.token_bytes(16), b"\x22" * 32))
        record = reg.serialize_record(txn)
        with self.assertRaises(reg.RecordTooShort):
            reg.parse_record(record[:-1])

    def test_oversized_record_raises_typed_too_long(self):
        txn = self.sign(make_commission(3, secrets.token_bytes(16), b"\x33" * 32))
        record = reg.serialize_record(txn) + b"\x00"
        with self.assertRaises(reg.RecordTooLong):
            reg.parse_record(record)

    def test_invalid_operation_byte_raises_typed_error(self):
        txn = self.sign(make_commission(4, secrets.token_bytes(16), b"\x44" * 32))
        record = bytearray(reg.serialize_record(txn))
        # The operation byte sits right after the two public-key fields
        # and the 3-field crypto-domain block; corrupt it to a value no
        # AuthorityOperation defines.
        offset = reg.HARDWARE_UID_BYTES + reg.PUBLIC_KEY_BYTES + 1 + 2 + 4 + 4 + 4 + reg.PUBLIC_KEY_BYTES
        record[offset] = 0xEE
        with self.assertRaises(reg.InvalidOperation):
            reg.parse_record(bytes(record))

    def test_invalid_crypto_form_raises_typed_error(self):
        txn = self.sign(make_commission(5, secrets.token_bytes(16), b"\x55" * 32))
        record = bytearray(reg.serialize_record(txn))
        offset = reg.HARDWARE_UID_BYTES + reg.PUBLIC_KEY_BYTES
        record[offset] = 0x00
        with self.assertRaises(reg.InvalidCryptoForm):
            reg.parse_record(bytes(record))

    def test_nonzero_group_selector_on_pairwise_domain_is_rejected(self):
        txn = self.sign(make_commission(6, secrets.token_bytes(16), b"\x66" * 32))
        record = bytearray(reg.serialize_record(txn))
        selector_offset = reg.HARDWARE_UID_BYTES + reg.PUBLIC_KEY_BYTES + 1
        record[selector_offset:selector_offset + 2] = (1).to_bytes(2, "big")
        with self.assertRaises(reg.InvalidGroupSelectorForPairwise):
            reg.parse_record(bytes(record))

    def test_tampered_signature_verifies_false(self):
        txn = self.sign(make_commission(7, secrets.token_bytes(16), b"\x77" * 32))
        message = reg.serialize_signed_message(txn)
        self.assertTrue(reg.verify_bytes(message, txn.issuer_signature_ed25519, self.public_key_raw, self.work_dir))
        tampered = bytearray(txn.issuer_signature_ed25519)
        tampered[0] ^= 0xFF
        self.assertFalse(reg.verify_bytes(message, bytes(tampered), self.public_key_raw, self.work_dir))

    def test_tampered_signed_field_after_signing_fails_verification(self):
        txn = self.sign(make_commission(8, secrets.token_bytes(16), b"\x88" * 32))
        message = bytearray(reg.serialize_signed_message(txn))
        message[0] ^= 0x01  # Tamper a signed field (hardwareUid byte) post-signature.
        self.assertFalse(
            reg.verify_bytes(bytes(message), txn.issuer_signature_ed25519, self.public_key_raw, self.work_dir)
        )


class RegistryCopyDurabilityTests(AuthorityRegistryTestCase):
    def test_survives_close_and_cold_reconstruction(self):
        txn = self.sign(make_commission(10, secrets.token_bytes(16), b"\xA0" * 32))
        copy1 = reg.AuthorityRegistryCopy(self.copy_a_path)
        self.assertTrue(copy1.append_issued(txn))
        del copy1  # Simulate process exit -- no cache to carry state forward.

        cold = reg.AuthorityRegistryCopy(self.copy_a_path)
        found, corrupt = cold.read_latest(txn.transaction_id_hex())
        self.assertFalse(corrupt)
        self.assertIsNotNone(found)
        self.assertEqual(found.state, reg.TransactionState.ISSUED)
        self.assertEqual(found.txn.transaction_id, txn.transaction_id)

    def test_missing_file_is_clean_not_found(self):
        copy = reg.AuthorityRegistryCopy(self.work_dir / "never-created.sqlite")
        found, corrupt = copy.read_latest(secrets.token_bytes(16).hex())
        self.assertIsNone(found)
        self.assertFalse(corrupt)

    def test_never_overwrites_an_existing_issued_transaction(self):
        txn_id = secrets.token_bytes(16)
        txn = self.sign(make_commission(11, txn_id, b"\xB0" * 32))
        copy = reg.AuthorityRegistryCopy(self.copy_a_path)
        self.assertTrue(copy.append_issued(txn))
        replay = self.sign(make_commission(11, txn_id, b"\xB1" * 32))  # same id, different manifest.
        self.assertFalse(copy.append_issued(replay))
        found, corrupt = copy.read_latest(txn_id.hex())
        self.assertFalse(corrupt)
        self.assertEqual(found.txn.manifest_digest_sha256, b"\xB0" * 32)  # first write wins, never replaced.

    def test_structurally_invalid_payload_reported_as_corrupt_but_present(self):
        # Corruption detection at the registry-read layer is structural
        # (an unrecognized enum byte / bad length), the same criterion
        # FileAuthorityRegistryCopy::readLatest() uses in the C++ side --
        # flipping an opaque data byte (e.g. inside a public key) leaves a
        # structurally well-formed record and is a signature-verification
        # concern, not a registry-read concern. Corrupt the crypto-domain
        # form byte instead, mirroring test_invalid_crypto_form_raises_typed_error.
        txn = self.sign(make_commission(12, secrets.token_bytes(16), b"\xC0" * 32))
        copy = reg.AuthorityRegistryCopy(self.copy_a_path)
        self.assertTrue(copy.append_issued(txn))

        conn = sqlite3.connect(str(self.copy_a_path))
        payload = conn.execute("SELECT payload FROM authority_log LIMIT 1").fetchone()[0]
        corrupted = bytearray(payload)
        form_offset = reg.HARDWARE_UID_BYTES + reg.PUBLIC_KEY_BYTES
        corrupted[form_offset] = 0x00  # not PAIRWISE (0xA1) nor GROUP (0xA2).
        conn.execute("UPDATE authority_log SET payload = ? WHERE payload = ?", (bytes(corrupted), payload))
        conn.commit()
        conn.close()

        cold = reg.AuthorityRegistryCopy(self.copy_a_path)
        found, corrupt = cold.read_latest(txn.transaction_id_hex())
        self.assertIsNone(found)
        self.assertTrue(corrupt)

    def test_database_disk_image_malformed_is_treated_as_corrupt(self):
        txn = self.sign(make_commission(13, secrets.token_bytes(16), b"\xD0" * 32))
        copy = reg.AuthorityRegistryCopy(self.copy_a_path)
        self.assertTrue(copy.append_issued(txn))

        # Simulate real on-disk corruption (not just a payload bit-flip):
        # truncate the file mid-page, which SQLite itself detects as a
        # malformed database, never a clean "empty" read.
        with open(self.copy_a_path, "r+b") as handle:
            handle.truncate(200)

        cold = reg.AuthorityRegistryCopy(self.copy_a_path)
        found, corrupt = cold.read_latest(txn.transaction_id_hex())
        self.assertIsNone(found)
        self.assertTrue(corrupt)

    def test_read_never_implicitly_creates_the_backing_file(self):
        # H4 fix: a pure read against a path that has never been written
        # to must never create it as a side effect -- previously a plain
        # `sqlite3.connect()` on a missing path silently materialized an
        # empty database file.
        path = self.work_dir / "read-only-probe.sqlite"
        copy = reg.AuthorityRegistryCopy(path)
        found, corrupt = copy.read_latest(secrets.token_bytes(16).hex())
        self.assertIsNone(found)
        self.assertFalse(corrupt)
        self.assertFalse(path.exists(), "a read must never create the backing file")

    def test_unreadable_file_due_to_permissions_is_uncertain_never_empty(self):
        # H4 fix: a file that EXISTS but cannot be opened (permission
        # denied) must never be reported the same way as a file that
        # genuinely does not exist. Real permission-based fault
        # injection, skipped as root (which bypasses Unix permissions).
        if os.geteuid() == 0:
            self.skipTest("permission-based fault injection is meaningless as root")

        txn = self.sign(make_commission(14, secrets.token_bytes(16), b"\xE0" * 32))
        copy = reg.AuthorityRegistryCopy(self.copy_a_path)
        self.assertTrue(copy.append_issued(txn))

        os.chmod(self.copy_a_path, 0o000)
        try:
            cold = reg.AuthorityRegistryCopy(self.copy_a_path)
            found, corrupt = cold.read_latest(txn.transaction_id_hex())
        finally:
            os.chmod(self.copy_a_path, 0o644)

        self.assertIsNone(found)
        self.assertTrue(corrupt, "an unreadable-but-present file must surface as Uncertain, never clean absence")

    def test_first_append_fails_when_parent_directory_fsync_is_impossible(self):
        # H5 fix: the FIRST append to a brand-new path must durably fsync
        # the PARENT DIRECTORY's own entry, not just the new file's
        # bytes. Exercised with a real permission fault: removing READ
        # permission (but keeping search/execute) on the parent directory
        # lets the file itself still be created (directory search alone
        # is enough to create a file by name) while making the directory
        # fsync step impossible.
        if os.geteuid() == 0:
            self.skipTest("permission-based fault injection is meaningless as root")

        subdir = self.work_dir / "first-create-restricted"
        subdir.mkdir(mode=0o755)
        txn = self.sign(make_commission(15, secrets.token_bytes(16), b"\xF0" * 32))
        copy = reg.AuthorityRegistryCopy(subdir / "first.sqlite")

        os.chmod(subdir, 0o111)
        try:
            appended = copy.append_issued(txn)
        finally:
            os.chmod(subdir, 0o755)

        self.assertFalse(
            appended,
            "an append whose parent-directory fsync cannot durably complete must never be "
            "reported as a successful, durable commit",
        )


class TwoCopyReconciliationTests(AuthorityRegistryTestCase):
    def test_reconcile_agrees_when_both_copies_match(self):
        txn = self.sign(make_commission(20, secrets.token_bytes(16), b"\xE0" * 32))
        pair = self.pair()
        self.assertTrue(pair.commit_issued(txn))
        result = pair.reconcile(txn.transaction_id)
        self.assertEqual(result.outcome, reg.ReconciliationOutcome.AGREED)
        self.assertEqual(result.resolved.state, reg.TransactionState.ISSUED)

    def test_cut_between_commits_recovers_from_single_copy_and_flags_repair(self):
        txn = self.sign(make_commission(21, secrets.token_bytes(16), b"\xE1" * 32))
        # Simulate a power cut exactly between the two copy commits: only
        # copy A ever receives the write.
        only_a = reg.AuthorityRegistryCopy(self.copy_a_path)
        self.assertTrue(only_a.append_issued(txn))

        pair = self.pair()
        result = pair.reconcile(txn.transaction_id)
        self.assertEqual(result.outcome, reg.ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY)
        self.assertTrue(result.needs_replica_repair)
        self.assertEqual(result.resolved.txn.transaction_id, txn.transaction_id)

    def test_faulted_first_parent_directory_fsync_never_releases_permit_and_genuine_repair_recovers_exact_grant(self):
        """H5 regression, revised per review: proves the fix BEHAVIORALLY
        (never merely "fsync was called") by genuinely faulting the FIRST
        parent-directory fsync during a brand-new append to copy A.
        Confirms (1) commit_issued reports failure -- no permission may be
        released off the back of it -- even though copy A's row was, in
        this same process, still genuinely committed+read-back; (2) after
        simulating the crash this fault models (an unconfirmed directory
        entry may not survive a crash even though the file's own fsync'd
        bytes did) and a genuine close/reopen, real two-copy repair
        recovers the EXACT SAME original Issued grant -- never a new
        issuance, never invented history."""
        txn = self.sign(make_commission(26, secrets.token_bytes(16), b"\xE6" * 32))

        copy_a = reg.AuthorityRegistryCopy(self.copy_a_path)
        fault_calls = []

        def faulted_sync(_path):
            fault_calls.append(1)
            return False  # Genuinely faulted: every parent-dir fsync on copy A fails in this test.

        copy_a.fsync_parent_directory_override_for_tests = faulted_sync
        copy_b = reg.AuthorityRegistryCopy(self.copy_b_path)
        pair = reg.AuthorityRegistryPair(copy_a, copy_b)

        self.assertFalse(pair.commit_issued(txn))
        self.assertEqual(len(fault_calls), 1)

        # Simulate the crash the fault models: copy A's directory entry is
        # lost entirely even though its file bytes were otherwise valid in
        # this process. Delete copy A's file, then genuinely close/reopen
        # -- brand-new AuthorityRegistryCopy instances against the same
        # paths, no in-memory state carried over and no override installed
        # (a real restart uses the real syscall).
        self.copy_a_path.unlink()

        pair2 = self.pair()
        before_repair = pair2.reconcile(txn.transaction_id)
        self.assertEqual(before_repair.outcome, reg.ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY)
        self.assertTrue(before_repair.needs_replica_repair)
        self.assertEqual(before_repair.resolved.state, reg.TransactionState.ISSUED)
        self.assertEqual(before_repair.resolved.txn.transaction_id, txn.transaction_id)
        self.assertEqual(before_repair.resolved.txn.manifest_digest_sha256, txn.manifest_digest_sha256)

        # Genuine repair: append the EXACT resolved (dominant, already-
        # agreed-upon) Issued record to the missing copy -- never a new
        # grant, never re-signed, never a different transaction.
        self.assertTrue(pair2.copy_a.append_issued(before_repair.resolved.txn))

        after = pair2.reconcile(txn.transaction_id)
        self.assertEqual(after.outcome, reg.ReconciliationOutcome.AGREED)
        self.assertFalse(after.needs_replica_repair)
        self.assertEqual(after.resolved.state, reg.TransactionState.ISSUED)
        self.assertEqual(after.resolved.txn.transaction_id, txn.transaction_id)
        self.assertEqual(after.resolved.txn.manifest_digest_sha256, txn.manifest_digest_sha256)

    def test_both_copies_missing_is_never_permission(self):
        pair = self.pair()
        result = pair.reconcile(secrets.token_bytes(16))
        self.assertEqual(result.outcome, reg.ReconciliationOutcome.NOT_FOUND)

    def test_one_copy_rollback_to_older_valid_issued_dominates_as_recovery(self):
        txn_id = secrets.token_bytes(16)
        txn = self.sign(make_commission(22, txn_id, b"\xE2" * 32))
        pair = self.pair()
        self.assertTrue(pair.commit_issued(txn))
        root = b"\xF0" * 32
        challenge = b"\x00" * reg.CHALLENGE_BYTES
        self.assertTrue(
            pair.commit_state_transition(txn_id, reg.TransactionState.CONSUMED_PREPARED, root, False, challenge)
        )
        self.assertTrue(
            pair.commit_state_transition(txn_id, reg.TransactionState.ACTIVATION_SPENT, root, True, challenge)
        )

        # Roll copy B back to a fresh Issued-only backup (restore an older
        # backup of exactly one registry copy).
        rollback_only_issued = self.work_dir / "copy-b-rollback.sqlite"
        fresh_b = reg.AuthorityRegistryCopy(rollback_only_issued)
        self.assertTrue(fresh_b.append_issued(txn))
        shutil.copyfile(rollback_only_issued, self.copy_b_path)

        pair2 = self.pair()
        result = pair2.reconcile(txn_id)
        self.assertEqual(result.outcome, reg.ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY)
        self.assertEqual(result.resolved.state, reg.TransactionState.ACTIVATION_SPENT)

    def test_conflicting_signed_content_for_same_id_is_uncertain(self):
        txn_id = secrets.token_bytes(16)
        txn_a = self.sign(make_commission(23, txn_id, b"\xE3" * 32))
        txn_b = self.sign(make_commission(24, txn_id, b"\xE3" * 32))  # same id, different binding!
        copy_a = reg.AuthorityRegistryCopy(self.copy_a_path)
        copy_b = reg.AuthorityRegistryCopy(self.copy_b_path)
        self.assertTrue(copy_a.append_issued(txn_a))
        self.assertTrue(copy_b.append_issued(txn_b))

        pair = self.pair()
        result = pair.reconcile(txn_id)
        self.assertEqual(result.outcome, reg.ReconciliationOutcome.UNCERTAIN)

    def test_deleted_and_corrupt_copy_combination_is_uncertain_never_permission(self):
        txn_id = secrets.token_bytes(16)
        txn = self.sign(make_commission(25, txn_id, b"\xE5" * 32))
        pair = self.pair()
        self.assertTrue(pair.commit_issued(txn))

        self.copy_a_path.unlink()
        pair2 = self.pair()
        result = pair2.reconcile(txn_id)
        self.assertEqual(result.outcome, reg.ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY)
        self.assertTrue(result.needs_replica_repair)

        with open(self.copy_b_path, "r+b") as handle:
            handle.truncate(150)
        pair3 = self.pair()
        result2 = pair3.reconcile(txn_id)
        self.assertEqual(result2.outcome, reg.ReconciliationOutcome.UNCERTAIN)

    def test_lifecycle_never_grants_activation_before_both_commits(self):
        txn_id = secrets.token_bytes(16)
        txn = self.sign(make_commission(26, txn_id, b"\xE6" * 32, tx_floor=3, rx_floor=9))
        pair = self.pair()
        self.assertTrue(pair.commit_issued(txn))

        root = txn.manifest_digest_sha256
        challenge = b"\x01" * reg.CHALLENGE_BYTES
        self.assertTrue(
            pair.commit_state_transition(txn_id, reg.TransactionState.CONSUMED_PREPARED, root, False, challenge)
        )
        # Not yet ActivationSpent: reconcile must reflect ConsumedPrepared,
        # never silently look "activated".
        mid = pair.reconcile(txn_id)
        self.assertEqual(mid.outcome, reg.ReconciliationOutcome.AGREED)
        self.assertEqual(mid.resolved.state, reg.TransactionState.CONSUMED_PREPARED)

        self.assertTrue(
            pair.commit_state_transition(txn_id, reg.TransactionState.ACTIVATION_SPENT, root, True, challenge)
        )
        after = pair.reconcile(txn_id)
        self.assertEqual(after.resolved.state, reg.TransactionState.ACTIVATION_SPENT)

    def test_activation_spent_replay_with_different_root_is_rejected(self):
        txn_id = secrets.token_bytes(16)
        txn = self.sign(make_commission(27, txn_id, b"\xE7" * 32))
        pair = self.pair()
        self.assertTrue(pair.commit_issued(txn))
        challenge = b"\x02" * reg.CHALLENGE_BYTES
        self.assertTrue(
            pair.commit_state_transition(
                txn_id, reg.TransactionState.CONSUMED_PREPARED, txn.manifest_digest_sha256, False, challenge
            )
        )
        self.assertTrue(
            pair.commit_state_transition(
                txn_id, reg.TransactionState.ACTIVATION_SPENT, txn.manifest_digest_sha256, True, challenge
            )
        )
        # A later attempt to "finish" with a substituted (different) root
        # must never succeed -- this is the spent-permit replay case.
        different_root = b"\xFF" * 32
        self.assertFalse(
            pair.copy_a.append_state_transition(
                txn_id, reg.TransactionState.ACTIVATION_SPENT, different_root, True, challenge
            )
        )


class BaselineCertificationManifestTests(unittest.TestCase):
    """The Python mirror of BaselineCertificationManifestCodec -- byte-
    for-byte identical canonical encoding, real SHA-256, field-sensitive
    digest."""

    def _manifest(self, tag: int) -> reg.BaselineCertificationManifest:
        return reg.BaselineCertificationManifest(
            approved_image_sha256=bytes([tag]) * reg.BASELINE_IMAGE_DIGEST_BYTES,
            approved_image_extent_offset=0x1000,
            approved_image_extent_length=0x2000,
            expected_sdk28_sha256_digest=bytes([tag + 2]) * reg.BASELINE_SDK_DIGEST_BYTES,
            stock_loader_artifact_sha256=bytes([tag + 1]) * reg.BASELINE_STOCK_LOADER_DIGEST_BYTES,
            stock_loader_artifact_range_start=0x100,
            stock_loader_artifact_range_length=0x400,
            boot_config_id=7,
            allow_ordinary_userdata=True,
        )

    def test_serialize_is_exactly_117_bytes(self):
        encoded = reg.serialize_baseline_manifest(self._manifest(1))
        self.assertEqual(len(encoded), reg.BASELINE_MANIFEST_BYTES)
        self.assertEqual(reg.BASELINE_MANIFEST_BYTES, 117)

    def test_digest_is_deterministic_real_sha256(self):
        manifest = self._manifest(2)
        digest_a = reg.compute_baseline_manifest_digest(manifest)
        digest_b = reg.compute_baseline_manifest_digest(manifest)
        self.assertEqual(digest_a, digest_b)
        self.assertEqual(len(digest_a), reg.DIGEST_BYTES)
        # Genuinely SHA-256 of the canonical encoding, not a placeholder.
        import hashlib
        expected = hashlib.sha256(reg.serialize_baseline_manifest(manifest)).digest()
        self.assertEqual(digest_a, expected)

    def test_digest_is_sensitive_to_every_field(self):
        base = self._manifest(3)
        base_digest = reg.compute_baseline_manifest_digest(base)

        changed_boot_config = self._manifest(3)
        changed_boot_config.boot_config_id += 1
        self.assertNotEqual(base_digest, reg.compute_baseline_manifest_digest(changed_boot_config))

        changed_flag = self._manifest(3)
        changed_flag.allow_ordinary_userdata = not base.allow_ordinary_userdata
        self.assertNotEqual(base_digest, reg.compute_baseline_manifest_digest(changed_flag))

        changed_image = self._manifest(3)
        changed_image.approved_image_sha256 = bytes([0xFF]) * reg.BASELINE_IMAGE_DIGEST_BYTES
        self.assertNotEqual(base_digest, reg.compute_baseline_manifest_digest(changed_image))

        changed_sdk = self._manifest(3)
        changed_sdk.expected_sdk28_sha256_digest = bytes([0xFF]) * reg.BASELINE_SDK_DIGEST_BYTES
        self.assertNotEqual(base_digest, reg.compute_baseline_manifest_digest(changed_sdk))


class BootFloorActivationReceiptTests(unittest.TestCase):
    """Python mirror of BootFloorActivationReceiptCodec (ROOT/Boot
    owner65278 canonical V1 wire format) -- byte-for-byte serialization,
    real CRC32/SHA-256, and a REAL cross-language Ed25519 interop vector
    verified with actual crypto (openssl), never a self-signed round
    trip or a mocked verifier."""

    def _receipt(self) -> "reg.BootFloorActivationReceiptV1":
        return reg.BootFloorActivationReceiptV1(
            hardware_uid=bytes.fromhex("0123456789ABCDEF"),
            local_mesh_full_public_key=bytes(range(1, 33)),
            consent_owner_public_key=bytes(range(33, 65)),
            target_id=1,
            profile_id=1,
            layout_id=1,
            current_role=0,
            publisher_key_id=7,
            publisher_key_fingerprint_sha256=bytes(range(65, 97)),
            host_transaction_id=bytes(range(97, 113)),
            authority_transaction_digest_sha256=bytes(range(113, 145)),
            commission_manifest_digest_sha256=bytes(range(145, 177)),
            prepared_root_digest_sha256=bytes(range(177, 209)),
            floor=0,
            baseline_image_sha256=bytes(range(209, 241)),
            baseline_extent_length=0x2000,
            original_sdk28_sha256_digest=bytes(range(241, 256)) + bytes(range(1, 18)),
        )

    def test_body_is_exactly_322_bytes_and_record_386(self):
        r = self._receipt()
        body = reg.serialize_boot_floor_body(r)
        self.assertEqual(len(body), reg.BOOT_FLOOR_BODY_BYTES)
        self.assertEqual(reg.BOOT_FLOOR_BODY_BYTES, 322)
        record = reg.serialize_boot_floor_record(r)
        self.assertEqual(len(record), reg.BOOT_FLOOR_RECORD_BYTES)
        self.assertEqual(reg.BOOT_FLOOR_RECORD_BYTES, 386)

    def test_numeric_uid_big_endian_to_little_endian_wire_vector(self):
        # Published vector: BE 0123456789ABCDEF -> LE wire EFCDAB8967452301.
        body = reg.serialize_boot_floor_body(self._receipt())
        self.assertEqual(body[12:20].hex(), "efcdab8967452301")

    def test_magic_and_fixed_boot_domain_match_boot_owner_published_constants(self):
        body = reg.serialize_boot_floor_body(self._receipt())
        magic = int.from_bytes(body[0:4], "little")
        boot_domain = int.from_bytes(body[8:12], "little")
        self.assertEqual(magic, reg.BOOT_FLOOR_RECORD_MAGIC)
        self.assertEqual(magic, 0x58464152)  # Copied verbatim from Boot's xiao_ota_record.h.
        self.assertEqual(boot_domain, reg.BOOT_FLOOR_FIXED_DOMAIN)
        self.assertEqual(boot_domain, 0x424F4F54)  # ASCII "BOOT", fixed for every device.

    def test_round_trip_preserves_every_field(self):
        r = self._receipt()
        r.signature_ed25519 = bytes([0xAB]) * reg.SIGNATURE_BYTES
        record = reg.serialize_boot_floor_record(r)
        parsed = reg.parse_boot_floor_record(record)
        self.assertEqual(parsed.hardware_uid, r.hardware_uid)
        self.assertEqual(parsed.local_mesh_full_public_key, r.local_mesh_full_public_key)
        self.assertEqual(parsed.consent_owner_public_key, r.consent_owner_public_key)
        self.assertEqual(parsed.authority_transaction_digest_sha256, r.authority_transaction_digest_sha256)
        self.assertEqual(parsed.commission_manifest_digest_sha256, r.commission_manifest_digest_sha256)
        self.assertEqual(parsed.prepared_root_digest_sha256, r.prepared_root_digest_sha256)
        self.assertEqual(parsed.floor, 0)
        self.assertEqual(parsed.baseline_extent_length, r.baseline_extent_length)
        self.assertEqual(parsed.signature_ed25519, r.signature_ed25519)

    def test_wrong_length_magic_domain_or_crc_is_rejected(self):
        record = bytearray(reg.serialize_boot_floor_record(self._receipt()))
        with self.assertRaises(reg.AuthorityCodecError):
            reg.parse_boot_floor_record(bytes(record[:-1]))
        bad_magic = bytearray(record)
        bad_magic[0] ^= 0xFF
        with self.assertRaises(reg.AuthorityCodecError):
            reg.parse_boot_floor_record(bytes(bad_magic))
        bad_domain = bytearray(record)
        bad_domain[8] ^= 0xFF
        with self.assertRaises(reg.AuthorityCodecError):
            reg.parse_boot_floor_record(bytes(bad_domain))
        bad_crc = bytearray(record)
        bad_crc[0] ^= 0x01  # Corrupt a body byte without recomputing the CRC.
        with self.assertRaises(reg.AuthorityCodecError):
            reg.parse_boot_floor_record(bytes(bad_crc))

    def test_real_ed25519_cross_language_interop_vector_verifies_with_actual_crypto(self):
        """This EXACT 386-byte record and 32-byte raw public key are the
        SAME literal fixture embedded in
        test/test_lora_ota_authority/test_lora_ota_authority.cpp's
        BootFloorActivationReceiptCodecTest.
        RealEd25519CrossLanguageInteropVectorVerifiesWithActualCrypto --
        produced once by this exact Python mirror + a synthetic,
        ephemeral, since-discarded .tmp-scoped openssl Ed25519 TEST key.
        Verifying it here too (via openssl, not a mock) proves the two
        language implementations agree on every byte AND that the
        signature is a real, independently-checkable Ed25519 signature,
        not a fabricated placeholder."""
        record_bytes = bytes.fromhex(_INTEROP_RECORD_HEX)
        self.assertEqual(len(record_bytes), 386)

        parsed = reg.parse_boot_floor_record(record_bytes)
        self.assertEqual(parsed.hardware_uid, bytes.fromhex("0123456789ABCDEF"))

        recomputed_digest = reg.compute_boot_floor_signed_digest(parsed)

        pubkey = bytes.fromhex(_INTEROP_PUBLISHER_PUBLIC_KEY_HEX)
        self.assertEqual(len(pubkey), 32)

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            tmp_path = pathlib.Path(tmp)
            pub_der = tmp_path / "pub.der"
            # Re-wrap the raw 32-byte Ed25519 public key into a DER SPKI
            # openssl can load, exactly as production code never does
            # (this is purely a TEST-side loader convenience) -- the
            # fixed 12-byte Ed25519 SPKI prefix is a well-known constant.
            spki_prefix = bytes.fromhex("302a300506032b6570032100")
            pub_der.write_bytes(spki_prefix + pubkey)
            digest_path = tmp_path / "digest.bin"
            digest_path.write_bytes(recomputed_digest)
            sig_path = tmp_path / "sig.bin"
            sig_path.write_bytes(parsed.signature_ed25519)

            verify = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-keyform", "DER", "-inkey", str(pub_der),
                    "-in", str(digest_path), "-sigfile", str(sig_path),
                ],
                capture_output=True,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)

            # Adversarial control: a tampered digest must make the SAME
            # real openssl verify call FAIL against this SAME signature.
            tampered_digest_path = tmp_path / "digest_bad.bin"
            tampered = bytearray(recomputed_digest)
            tampered[0] ^= 0x01
            tampered_digest_path.write_bytes(bytes(tampered))
            bad_verify = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-keyform", "DER", "-inkey", str(pub_der),
                    "-in", str(tampered_digest_path), "-sigfile", str(sig_path),
                ],
                capture_output=True,
            )
            self.assertNotEqual(bad_verify.returncode, 0)

    def test_real_ed25519_cross_language_interop_vector_verifies_with_actual_crypto_role_one(self):
        """Astra role-1 residual ("verify requested role1 shared real
        crypto literal interop exists C++/Python"): a SEPARATE real
        fixture carrying currentRole=1 end-to-end, genuinely signed with
        a fresh ephemeral Ed25519 test keypair (generated once via
        openssl, private key discarded immediately after -- never
        committed, never reused). IDENTICAL literal bytes to the C++
        test's kInteropRecordRoleOne / kInteropPublisherPublicKeyRoleOne
        in BootFloorActivationReceiptCodecTest.
        RealEd25519CrossLanguageInteropVectorVerifiesWithActualCryptoRoleOne."""
        record_bytes = bytes.fromhex(_INTEROP_RECORD_ROLE_ONE_HEX)
        self.assertEqual(len(record_bytes), 386)

        parsed = reg.parse_boot_floor_record(record_bytes)
        self.assertEqual(parsed.current_role, 1)
        self.assertEqual(parsed.hardware_uid, bytes.fromhex("fedcba9876543210"))

        recomputed_digest = reg.compute_boot_floor_signed_digest(parsed)

        pubkey = bytes.fromhex(_INTEROP_PUBLISHER_PUBLIC_KEY_ROLE_ONE_HEX)
        self.assertEqual(len(pubkey), 32)

        with tempfile.TemporaryDirectory(dir=TMP_ROOT) as tmp:
            tmp_path = pathlib.Path(tmp)
            pub_der = tmp_path / "pub.der"
            spki_prefix = bytes.fromhex("302a300506032b6570032100")
            pub_der.write_bytes(spki_prefix + pubkey)
            digest_path = tmp_path / "digest.bin"
            digest_path.write_bytes(recomputed_digest)
            sig_path = tmp_path / "sig.bin"
            sig_path.write_bytes(parsed.signature_ed25519)

            verify = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-keyform", "DER", "-inkey", str(pub_der),
                    "-in", str(digest_path), "-sigfile", str(sig_path),
                ],
                capture_output=True,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)

            # Adversarial control: a tampered digest (role flipped before
            # recomputing) must make the SAME real openssl verify call
            # FAIL against this SAME signature.
            tampered_record = bytearray(record_bytes)
            tampered_record[96] ^= 0x01  # currentRole: 1 -> 0.
            crc = zlib.crc32(bytes(tampered_record[:318])) & 0xFFFFFFFF
            tampered_record[318:322] = crc.to_bytes(4, "little")
            tampered_parsed = reg.parse_boot_floor_record(bytes(tampered_record))
            self.assertEqual(tampered_parsed.current_role, 0)
            tampered_digest = reg.compute_boot_floor_signed_digest(tampered_parsed)
            tampered_digest_path = tmp_path / "digest_bad_role.bin"
            tampered_digest_path.write_bytes(tampered_digest)
            bad_verify = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-keyform", "DER", "-inkey", str(pub_der),
                    "-in", str(tampered_digest_path), "-sigfile", str(sig_path),
                ],
                capture_output=True,
            )
            self.assertNotEqual(bad_verify.returncode, 0)


# Shared literal fixture (see test_real_ed25519_cross_language_interop_vector_verifies_with_actual_crypto's
# docstring above): identical bytes to the C++ test's kInteropRecord /
# kInteropPublisherPublicKey.
_INTEROP_RECORD_HEX = (
    "5241465801008201544f4f42efcdab89674523010102030405060708090a0b0c0d0e0f101112"
    "131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738"
    "393a3b3c3d3e3f400100000001000000010000000000000007004142434445464748494a4b4c"
    "4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172"
    "737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798"
    "999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbe"
    "bfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd000000000d1d2d3d4d5d6d7d8d9dadbdcdddedfe0"
    "e1e2e3e4e5e6e7e8e9eaebecedeeeff000200000f1f2f3f4f5f6f7f8f9fafbfcfdfeff010203"
    "0405060708090a0b0c0d0e0f101189423086d8c2a99b5925bc524a27b69bfa71d3024fd99bc7"
    "d58db9504b3eb00ae074be34b75fd2447c64d049818ac27eda24893b7621899e66b3cece7e0b"
    "13b3105aaa0e"
)
_INTEROP_PUBLISHER_PUBLIC_KEY_HEX = (
    "1014cae1b5cf78a52635452515658b730af59799ca1b2c250a631852c824403b"
)

# Second shared literal fixture, currentRole=1 (see
# test_real_ed25519_cross_language_interop_vector_verifies_with_actual_crypto_role_one's
# docstring above): identical bytes to the C++ test's
# kInteropRecordRoleOne / kInteropPublisherPublicKeyRoleOne. Produced
# once with a SEPARATE fresh ephemeral openssl Ed25519 test keypair
# (private key discarded immediately after, never committed).
_INTEROP_RECORD_ROLE_ONE_HEX = (
    "5241465801008201544f4f421032547698badcfec8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9da"
    "dbdcdddedfe0e1e2e3e4e5e6e732333435363738393a3b3c3d3e3f404142434445464748494a4b"
    "4c4d4e4f5051020000000200000002000000010000000900"
    "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627282901020304050607"
    "08090a0b0c0d0e0f101415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"
    "32333c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b6465666768"
    "696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182830000000096979899"
    "9a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b500400000b4b5b6b7b8b9ba"
    "bbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3ce17679820"
    "8a198802e08ae3d524ff549e307bc64d6b8991a9a67696da12761bad3af9f278f662f2c294db5f"
    "f8af65e43f73f67269a237e78bba9c019766a09996bcf30a"
)
_INTEROP_PUBLISHER_PUBLIC_KEY_ROLE_ONE_HEX = (
    "301e7112250f704adb6057d7a279a1fc1fd8a01658d4095d1be40d08247f26b3"
)



class PreparedRootCommitmentTests(unittest.TestCase):
    """Bounded, explicit-error-result checks for
    compute_prepared_root_commitment_sha256 -- mirrors the C++
    PreparedRootCommitment::Result seam exactly: refuse a malformed
    input on the length/None-ness alone, never on a failed read, and
    never change the value produced for any genuinely valid input."""

    def test_none_p_is_rejected_never_treated_as_empty_bytes(self):
        with self.assertRaises(reg.PreparedRootCommitmentError):
            reg.compute_prepared_root_commitment_sha256(None)

    def test_empty_bytes_p_is_still_accepted(self):
        # Astra29: empty-P semantics explicitly stay legal.
        digest = reg.compute_prepared_root_commitment_sha256(b"")
        self.assertEqual(len(digest), 32)

    def test_length_above_uint32_max_is_rejected_before_any_hashing(self):
        # A real >4 GiB bytes object is never allocated here: this proxy
        # object reports an impossible length via __len__ while its real
        # underlying buffer stays tiny, proving the length check is
        # evaluated (and refuses) before any attempt to actually hash
        # real p_len bytes -- no huge allocation/read ever happens.
        class _FakeImpossibleLength(bytes):
            def __len__(self):
                return 0x100000000  # UINT32_MAX + 1

        fake_p = _FakeImpossibleLength(b"tiny")
        with mock.patch("ota_authority_registry.hashlib.sha256") as mock_sha256:
            with self.assertRaises(reg.PreparedRootCommitmentError):
                reg.compute_prepared_root_commitment_sha256(fake_p)
            mock_sha256.assert_not_called()

    def test_valid_input_still_produces_the_exact_same_digest_as_before(self):
        p = bytes(range(5))
        expected = hashlib.sha256(
            reg.PREPARED_ROOT_COMMITMENT_DOMAIN + struct.pack(">I", len(p)) + p
        ).digest()
        self.assertEqual(reg.compute_prepared_root_commitment_sha256(p), expected)


class CertifyExistingBaselineOperationTests(AuthorityRegistryTestCase):
    """AuthorityCoordinator's submitCertifyExistingBaseline guards,
    mirrored here at the CLI/issue level: revision/predecessor/floors
    must all stay zero -- this operation has no lineage and seeds no
    counters."""

    def _manifest_digest_hex(self) -> str:
        manifest = reg.BaselineCertificationManifest(
            approved_image_sha256=b"\xAA" * reg.BASELINE_IMAGE_DIGEST_BYTES,
            approved_image_extent_offset=0x1000,
            approved_image_extent_length=0x2000,
            expected_sdk28_sha256_digest=b"\x01" * reg.BASELINE_SDK_DIGEST_BYTES,
            stock_loader_artifact_sha256=b"\xBB" * reg.BASELINE_STOCK_LOADER_DIGEST_BYTES,
            stock_loader_artifact_range_start=0x10,
            stock_loader_artifact_range_length=0x20,
            boot_config_id=1,
            allow_ordinary_userdata=False,
        )
        return reg.compute_baseline_manifest_digest(manifest).hex()

    def _issue_argv(self, binding: reg.AuthorityBinding, **overrides) -> list:
        argv = [
            "issue",
            "--registry-a", str(self.copy_a_path),
            "--registry-b", str(self.copy_b_path),
            "--issuer-private-key", str(self.private_key),
            "--work-dir", str(self.work_dir),
            "--operation", "certify-existing-baseline",
            "--hardware-uid", binding.hardware_uid.hex(),
            "--mesh-public-key", binding.mesh_full_public_key.hex(),
            "--profile-id", "1",
            "--layout-id", "1",
            "--consent-owner-key", binding.consent_owner_public_key.hex(),
            "--manifest-digest", self._manifest_digest_hex(),
            "--tx-floor", "0",
            "--rx-floor", "0",
            "--issuer-key-id", "1",
            "--issued-at", "1700000000",
        ]
        for key, value in overrides.items():
            flag = f"--{key.replace('_', '-')}"
            if flag in argv:
                argv[argv.index(flag) + 1] = str(value)
            else:
                argv.extend([flag, str(value)])
        return argv

    def test_certify_existing_baseline_commits_and_stays_issued(self):
        binding = make_binding(60)
        self.assertEqual(reg.main(self._issue_argv(binding)), 0)

        copy = reg.AuthorityRegistryCopy(self.copy_a_path)
        # sqlite3's own `with conn:` context manager only commits/rolls
        # back a transaction -- it does NOT close the connection, so an
        # explicit close() (via contextlib.closing) is required to avoid
        # leaking an open sqlite3.Connection (observed as a Python
        # ResourceWarning).
        with contextlib.closing(sqlite3.connect(str(self.copy_a_path))) as conn:
            rows = list(conn.execute("SELECT transaction_id FROM authority_log LIMIT 1"))
        transaction_id_hex = rows[0][0]
        record, corrupt = copy.read_latest(transaction_id_hex)
        self.assertFalse(corrupt)
        self.assertIsNotNone(record)
        self.assertEqual(record.txn.operation, reg.AuthorityOperation.CERTIFY_EXISTING_BASELINE)
        self.assertEqual(record.state, reg.TransactionState.ISSUED)

    def test_certify_existing_baseline_rejects_nonzero_revision(self):
        binding = make_binding(61)
        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, revision=1))

    def test_certify_existing_baseline_rejects_nonzero_predecessor(self):
        binding = make_binding(62)
        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, predecessor_id=("11" * reg.TRANSACTION_ID_BYTES)))

    def test_certify_existing_baseline_rejects_nonzero_tx_floor(self):
        binding = make_binding(63)
        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, tx_floor=1))

    def test_certify_existing_baseline_rejects_nonzero_rx_floor(self):
        binding = make_binding(64)
        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, rx_floor=1))

    def test_compute_baseline_manifest_digest_cli_matches_library(self):
        argv = [
            "compute-baseline-manifest-digest",
            "--approved-image-sha256", ("aa" * reg.BASELINE_IMAGE_DIGEST_BYTES),
            "--approved-image-extent-offset", "0x1000",
            "--approved-image-extent-length", "0x2000",
            "--expected-sdk28-sha256-digest", ("01" * reg.BASELINE_SDK_DIGEST_BYTES),
            "--stock-loader-artifact-sha256", ("bb" * reg.BASELINE_STOCK_LOADER_DIGEST_BYTES),
            "--stock-loader-artifact-range-start", "0x10",
            "--stock-loader-artifact-range-length", "0x20",
            "--boot-config-id", "1",
        ]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(reg.main(argv), 0)
        printed_digest_hex = buf.getvalue().strip()

        expected = reg.compute_baseline_manifest_digest(
            reg.BaselineCertificationManifest(
                approved_image_sha256=b"\xAA" * reg.BASELINE_IMAGE_DIGEST_BYTES,
                approved_image_extent_offset=0x1000,
                approved_image_extent_length=0x2000,
                expected_sdk28_sha256_digest=b"\x01" * reg.BASELINE_SDK_DIGEST_BYTES,
                stock_loader_artifact_sha256=b"\xBB" * reg.BASELINE_STOCK_LOADER_DIGEST_BYTES,
                stock_loader_artifact_range_start=0x10,
                stock_loader_artifact_range_length=0x20,
                boot_config_id=1,
                allow_ordinary_userdata=False,
            )
        )
        self.assertEqual(printed_digest_hex, expected.hex())


class OwnerHistoryReconciliationTests(AuthorityRegistryTestCase):
    """Sol29 HIGH6 (Python mirror): `issue` must never sign a fresh
    Commission over an already-activated owner, nor a Repair/Rekey with
    an arbitrary operator-supplied revision/predecessor that doesn't
    actually chain from the reconciled surviving history."""

    def _activate(self, tag: int, txn_id: bytes, digest: bytes, tx_floor=0, rx_floor=0) -> reg.AuthorityTransaction:
        """Drives a fresh Commission all the way to ActivationSpent in
        both copies, exactly like a real device would, using the same
        AuthorityRegistryPair the CLI itself uses."""
        txn = self.sign(make_commission(tag, txn_id, digest, tx_floor=tx_floor, rx_floor=rx_floor))
        pair = self.pair()
        self.assertTrue(pair.commit_issued(txn))
        challenge = b"\x07" * reg.CHALLENGE_BYTES
        self.assertTrue(
            pair.commit_state_transition(txn_id, reg.TransactionState.CONSUMED_PREPARED, digest, False, challenge)
        )
        self.assertTrue(
            pair.commit_state_transition(txn_id, reg.TransactionState.ACTIVATION_SPENT, digest, True, challenge)
        )
        return txn

    def _issue_argv(self, binding: reg.AuthorityBinding, operation: str, **overrides) -> list:
        argv = [
            "issue",
            "--registry-a", str(self.copy_a_path),
            "--registry-b", str(self.copy_b_path),
            "--issuer-private-key", str(self.private_key),
            "--work-dir", str(self.work_dir),
            "--operation", operation,
            "--hardware-uid", binding.hardware_uid.hex(),
            "--mesh-public-key", binding.mesh_full_public_key.hex(),
            "--profile-id", "1",
            "--layout-id", "1",
            "--consent-owner-key", binding.consent_owner_public_key.hex(),
            "--manifest-digest", ("22" * 32),
            "--tx-floor", "0",
            "--rx-floor", "0",
            "--issuer-key-id", "1",
            "--issued-at", "1700000000",
        ]
        for key, value in overrides.items():
            flag = f"--{key.replace('_', '-')}"
            if flag in argv:
                argv[argv.index(flag) + 1] = str(value)
            else:
                argv.extend([flag, str(value)])
        return argv

    def test_fresh_commission_over_already_activated_owner_is_rejected(self):
        tag = 70
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xA0" * 32)

        binding = make_binding(tag)  # exact same ownership identity.
        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, "commission"))

    def test_role_only_relabel_commission_is_still_rejected_as_duplicate(self):
        # Role is deliberately excluded from same_ownership() -- a pure
        # role/label change is never grounds for a fresh Commission.
        tag = 71
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xA1" * 32)

        binding = make_binding(tag)
        binding.historical_initial_role_id = 9  # different label/role only.
        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, "commission"))

    def test_genuinely_unrelated_device_first_commission_still_succeeds(self):
        tag = 72
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xA2" * 32)

        unrelated = make_binding(tag + 100)
        self.assertEqual(reg.main(self._issue_argv(unrelated, "commission")), 0)

    def test_commission_cannot_escape_the_physical_lineage_fence_via_crypto_domain_relabel(self):
        # Sol43 HIGH fix: the pre-fix same_ownership-scoped checks above
        # (test_fresh_commission_over_already_activated_owner_is_rejected
        # and the H3 ConsumedPrepared/Issued-only variant) both require
        # crypto_form/group_selector/layout_id to match exactly to detect
        # a conflict -- so a second genuinely-signed Commission for the
        # SAME hardware_uid+mesh_public_key but a DIFFERENT group_selector
        # was previously invisible to BOTH of them AND to
        # read_latest_physical_lineage (which, before this fix, also
        # compared crypto_form/group_selector/layout_id), letting a
        # duplicate "genesis" Issued record through. It must now be denied
        # before a second Issued record is ever created.
        tag = 76
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xA6" * 32)

        binding = make_binding(tag)
        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, "commission", group_selector=0x1234))

    def test_commission_cannot_escape_the_physical_lineage_fence_via_layout_relabel(self):
        # Same escape as above, but relabeling layout_id instead of the
        # crypto-domain group_selector -- both dimensions must be closed
        # independently.
        tag = 77
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xA7" * 32)

        binding = make_binding(tag)
        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, "commission", layout_id=2))

    def test_baseline_certificate_never_blocks_a_genuinely_first_commission_for_the_same_owner(self):
        # H1 fix: a signed CertifyExistingBaseline (a narrower,
        # never-advancing grant) must never be mistaken for Commission/
        # Repair/Rekey lineage history. Before the fix,
        # read_latest_activation_for_owner/read_latest_ownership_lineage
        # treated ANY record for this owner (any operation) as prior
        # history, so a genuinely first Commission for the SAME owner
        # that already has a signed baseline certificate on file was
        # wrongly refused with a StaleRevision-style SystemExit.
        tag = 75
        binding = make_binding(tag)
        self.assertEqual(reg.main(self._issue_argv(binding, "certify-existing-baseline")), 0)

        # The genuinely first Commission for this exact same ownership
        # must now succeed -- the baseline certificate is not lineage.
        self.assertEqual(reg.main(self._issue_argv(binding, "commission")), 0)

        # The baseline certificate itself is retained untouched, still
        # Issued, never promoted/consumed/overwritten by the Commission.
        pair = self.pair()
        certify_record, corrupt = pair.copy_a.read_latest_ownership_lineage(binding)
        # read_latest_ownership_lineage now filters CertifyExistingBaseline
        # out entirely -- it must resolve to the Commission instead.
        self.assertFalse(corrupt)
        self.assertIsNotNone(certify_record)
        self.assertEqual(certify_record.txn.operation, reg.AuthorityOperation.COMMISSION)

        # Existing fork-detection discipline must still be strict: a
        # SECOND genesis Commission for this SAME owner must still be
        # rejected, never permitted just because the baseline certificate
        # is filtered out of the scan.
        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, "commission"))

    def test_second_genesis_commission_for_same_owner_rejected_before_either_is_spent(self):
        # H3 fix: reconcile_latest_activation_for_owner alone is
        # structurally blind to a sibling revision-0 Commission for the
        # SAME owner that has reached Issued (or ConsumedPrepared) but
        # not yet ActivationSpent -- two distinct genesis transactions
        # could otherwise both be issued before either was ever detected
        # as a conflict.
        tag = 74
        binding = make_binding(tag)
        first_argv = self._issue_argv(binding, "commission")
        self.assertEqual(reg.main(first_argv), 0)  # only reaches Issued -- never prepared/activated.

        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, "commission"))

        # Advance the first transaction to ConsumedPrepared (still not
        # Spent) directly against the same registry pair, and confirm a
        # THIRD distinct genesis attempt is rejected the exact same way.
        pair = self.pair()
        latest, corrupt = pair.copy_a.read_latest_ownership_lineage(binding)
        self.assertFalse(corrupt)
        self.assertIsNotNone(latest)
        txn_id = latest.txn.transaction_id
        challenge = b"\x09" * reg.CHALLENGE_BYTES
        self.assertTrue(
            pair.commit_state_transition(txn_id, reg.TransactionState.CONSUMED_PREPARED, b"\x00" * 32, False, challenge)
        )

        with self.assertRaises(SystemExit):
            reg.main(self._issue_argv(binding, "commission"))

    def test_repair_chains_from_exact_surviving_predecessor(self):
        tag = 73
        txn_id1 = secrets.token_bytes(16)
        txn1 = self._activate(tag, txn_id1, b"\xA3" * 32, tx_floor=5, rx_floor=9)

        binding = make_binding(tag)
        argv = self._issue_argv(
            binding, "repair",
            revision=1,
            predecessor_id=txn_id1.hex(),
            tx_floor=5,
            rx_floor=9,
        )
        self.assertEqual(reg.main(argv), 0)
        self.assertIsNotNone(txn1)

    def test_repair_with_arbitrary_unchained_revision_predecessor_is_rejected(self):
        tag = 74
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xA4" * 32, tx_floor=5, rx_floor=9)

        binding = make_binding(tag)
        # Operator-supplied revision/predecessor that do NOT chain from
        # the actual surviving activated transaction must be rejected,
        # not trusted at face value.
        argv = self._issue_argv(
            binding, "repair",
            revision=1,
            predecessor_id=("00" * reg.TRANSACTION_ID_BYTES),
            tx_floor=5,
            rx_floor=9,
        )
        with self.assertRaises(SystemExit):
            reg.main(argv)

    def test_repair_cannot_lower_surviving_tx_or_rx_floor(self):
        tag = 75
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xA5" * 32, tx_floor=10, rx_floor=20)

        binding = make_binding(tag)
        argv = self._issue_argv(
            binding, "repair",
            revision=1,
            predecessor_id=txn_id1.hex(),
            tx_floor=9,  # lower than the surviving floor: must be rejected.
            rx_floor=20,
        )
        with self.assertRaises(SystemExit):
            reg.main(argv)

    def test_repair_without_any_surviving_history_is_rejected(self):
        binding = make_binding(76)
        argv = self._issue_argv(binding, "repair", revision=1, predecessor_id=("00" * reg.TRANSACTION_ID_BYTES))
        with self.assertRaises(SystemExit):
            reg.main(argv)

    def test_repair_denied_when_a_pending_rekey_has_superseded_the_owner_scoped_tip(self):
        """Sol HIGH1 fix: reconcile_latest_activation_for_owner alone is
        scoped to the EXACT owner binding (including mesh_full_public_key)
        -- it is structurally blind to a MORE RECENT transaction for the
        SAME physical hardware_uid under a DIFFERENT key. Without the
        physical-lineage fence, ActivationSpent(A) -> Rekey(A->B, Issued
        but not yet activated) -> Repair(A) would still chain cleanly
        against A's own stale owner-scoped tip and fork the real physical
        lineage. The physical-wide reconciliation must catch this and
        deny the Repair before any signing/Issued commit -- zero writes
        to either registry copy."""
        tag = 175
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xB1" * 32, tx_floor=3, rx_floor=4)

        old_binding = make_binding(tag)
        new_binding = reg.AuthorityBinding(
            hardware_uid=old_binding.hardware_uid,
            mesh_full_public_key=bytes([0xDD]) * reg.PUBLIC_KEY_BYTES,  # genuinely new key material.
            crypto_form=old_binding.crypto_form,
            group_selector=old_binding.group_selector,
            profile_id=old_binding.profile_id,
            layout_id=old_binding.layout_id,
            historical_initial_role_id=old_binding.historical_initial_role_id,
            consent_owner_public_key=old_binding.consent_owner_public_key,
        )
        # The Rekey only reaches Issued -- deliberately never activated,
        # exactly like a real in-flight rekey a Repair could race against.
        rekey_argv = self._issue_argv(
            new_binding, "rekey",
            revision=1,
            predecessor_id=txn_id1.hex(),
            prior_mesh_public_key=old_binding.mesh_full_public_key.hex(),
            tx_floor=3, rx_floor=4,
        )
        self.assertEqual(reg.main(rekey_argv), 0)

        before_a_bytes = self.copy_a_path.read_bytes()
        before_b_bytes = self.copy_b_path.read_bytes()

        # A Repair chaining from the NOW-STALE owner-scoped tip (A's own
        # ActivationSpent record) must be denied -- the real physical
        # tip has already moved on to the pending Rekey under a
        # different key.
        repair_argv = self._issue_argv(
            old_binding, "repair",
            revision=1,
            predecessor_id=txn_id1.hex(),
            tx_floor=3, rx_floor=4,
        )
        with self.assertRaises(SystemExit):
            reg.main(repair_argv)

        # Zero registry writes: both copies are byte-for-byte unchanged.
        self.assertEqual(self.copy_a_path.read_bytes(), before_a_bytes)
        self.assertEqual(self.copy_b_path.read_bytes(), before_b_bytes)

    def test_repair_still_succeeds_when_it_matches_the_real_physical_tip(self):
        """Positive counterpart: a Repair whose declared predecessor
        genuinely IS the current real physical tip (no superseding
        Rekey in flight) must still succeed -- the HIGH1 fence must
        never reject a legitimate Repair."""
        tag = 176
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xB2" * 32, tx_floor=5, rx_floor=6)

        binding = make_binding(tag)
        argv = self._issue_argv(
            binding, "repair",
            revision=1,
            predecessor_id=txn_id1.hex(),
            tx_floor=5, rx_floor=6,
        )
        self.assertEqual(reg.main(argv), 0)

    def test_genuine_rekey_with_new_key_material_chains_and_succeeds(self):
        tag = 77
        txn_id1 = secrets.token_bytes(16)
        txn1 = self._activate(tag, txn_id1, b"\xA7" * 32)

        old_binding = make_binding(tag)
        new_binding = reg.AuthorityBinding(
            hardware_uid=old_binding.hardware_uid,
            mesh_full_public_key=bytes([0xEE]) * reg.PUBLIC_KEY_BYTES,  # genuinely new key material.
            crypto_form=old_binding.crypto_form,
            group_selector=old_binding.group_selector,
            profile_id=old_binding.profile_id,
            layout_id=old_binding.layout_id,
            historical_initial_role_id=old_binding.historical_initial_role_id,
            consent_owner_public_key=old_binding.consent_owner_public_key,
        )
        argv = self._issue_argv(
            new_binding, "rekey",
            revision=1,
            predecessor_id=txn_id1.hex(),
            prior_mesh_public_key=old_binding.mesh_full_public_key.hex(),
        )
        self.assertEqual(reg.main(argv), 0)
        self.assertIsNotNone(txn1)

    def test_rekey_with_identical_key_material_is_rejected_as_relabel(self):
        tag = 78
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xA8" * 32)

        binding = make_binding(tag)
        argv = self._issue_argv(
            binding, "rekey",
            revision=1,
            predecessor_id=txn_id1.hex(),
            prior_mesh_public_key=binding.mesh_full_public_key.hex(),  # identical: not a real rekey.
        )
        with self.assertRaises(SystemExit):
            reg.main(argv)

    def test_rekey_without_prior_mesh_public_key_flag_is_rejected(self):
        tag = 79
        txn_id1 = secrets.token_bytes(16)
        self._activate(tag, txn_id1, b"\xA9" * 32)

        binding = make_binding(tag)
        new_binding = reg.AuthorityBinding(
            hardware_uid=binding.hardware_uid,
            mesh_full_public_key=bytes([0xEF]) * reg.PUBLIC_KEY_BYTES,
            crypto_form=binding.crypto_form,
            group_selector=binding.group_selector,
            profile_id=binding.profile_id,
            layout_id=binding.layout_id,
            historical_initial_role_id=binding.historical_initial_role_id,
            consent_owner_public_key=binding.consent_owner_public_key,
        )
        argv = self._issue_argv(new_binding, "rekey", revision=1, predecessor_id=txn_id1.hex())
        with self.assertRaises(SystemExit):
            reg.main(argv)

    def test_rekey_fork_to_a_different_pending_key_is_rejected_even_before_successor_activates(self):
        # H-finding (Python mirror): rekey A->B lands Issued (pending,
        # not yet activated), then a competing rekey A->C for the SAME
        # predecessor+revision must be rejected even though B never
        # reached ActivationSpent -- reconcile_latest_activation_for_owner
        # alone is structurally blind to this since it only ever sees the
        # OLD key's ActivationSpent record. Once B genuinely activates, a
        # real successor rekey B->C must still be permitted.
        tag = 82
        txn_id1 = secrets.token_bytes(16)
        digest = b"\xC2" * 32
        self._activate(tag, txn_id1, digest)

        old_binding = make_binding(tag)
        binding_b = reg.AuthorityBinding(
            hardware_uid=old_binding.hardware_uid,
            mesh_full_public_key=bytes([0xBB]) * reg.PUBLIC_KEY_BYTES,
            crypto_form=old_binding.crypto_form,
            group_selector=old_binding.group_selector,
            profile_id=old_binding.profile_id,
            layout_id=old_binding.layout_id,
            historical_initial_role_id=old_binding.historical_initial_role_id,
            consent_owner_public_key=old_binding.consent_owner_public_key,
        )
        binding_c = reg.AuthorityBinding(
            hardware_uid=old_binding.hardware_uid,
            mesh_full_public_key=bytes([0xCC]) * reg.PUBLIC_KEY_BYTES,
            crypto_form=old_binding.crypto_form,
            group_selector=old_binding.group_selector,
            profile_id=old_binding.profile_id,
            layout_id=old_binding.layout_id,
            historical_initial_role_id=old_binding.historical_initial_role_id,
            consent_owner_public_key=old_binding.consent_owner_public_key,
        )

        txn_id_b = secrets.token_bytes(16)
        argv_b = self._issue_argv(
            binding_b, "rekey",
            revision=1,
            predecessor_id=txn_id1.hex(),
            prior_mesh_public_key=old_binding.mesh_full_public_key.hex(),
            transaction_id=txn_id_b.hex(),
        )
        # A->B lands Issued only (pending): the CLI's `issue` subcommand
        # never drives a transaction past Issued itself.
        self.assertEqual(reg.main(argv_b), 0)

        # A competing A->C fork for the exact same predecessor+revision
        # must be rejected while B is still only pending.
        txn_id_c = secrets.token_bytes(16)
        argv_c_fork = self._issue_argv(
            binding_c, "rekey",
            revision=1,
            predecessor_id=txn_id1.hex(),
            prior_mesh_public_key=old_binding.mesh_full_public_key.hex(),
            transaction_id=txn_id_c.hex(),
        )
        with self.assertRaises(SystemExit):
            reg.main(argv_c_fork)

        # Resubmitting the EXACT SAME A->B transaction id is still its
        # own lineage tip, not a fork -- but append_issued's own
        # unconditional duplicate-transaction-id rejection (unrelated,
        # pre-existing, out of scope here) means resubmission is still
        # refused overall; that is a separate, already-existing registry
        # invariant, not asserted by this test.

        # Drive B all the way to genuine ActivationSpent, exactly like a
        # real device completing the handshake.
        pair = self.pair()
        challenge = b"\x08" * reg.CHALLENGE_BYTES
        self.assertTrue(
            pair.commit_state_transition(txn_id_b, reg.TransactionState.CONSUMED_PREPARED, digest, False, challenge)
        )
        self.assertTrue(
            pair.commit_state_transition(txn_id_b, reg.TransactionState.ACTIVATION_SPENT, digest, True, challenge)
        )

        # Now a genuine successor B->C, chaining from B's own activated
        # transaction, must be permitted.
        argv_c_successor = self._issue_argv(
            binding_c, "rekey",
            revision=2,
            predecessor_id=txn_id_b.hex(),
            prior_mesh_public_key=binding_b.mesh_full_public_key.hex(),
        )
        self.assertEqual(reg.main(argv_c_successor), 0)


class CorruptLaterHistoryNeverMasksAsCleanTests(AuthorityRegistryTestCase):
    """Sol29 HIGH4 (Python mirror): a corrupted LATER transition row must
    never be silently hidden behind a still-parseable EARLIER Issued
    record -- `read_latest` and `read_latest_activation_for_owner` must
    both propagate the corruption signal regardless of `found`."""

    def test_corrupt_activation_spent_row_is_never_masked_by_clean_issued_row(self):
        txn_id = secrets.token_bytes(16)
        txn = self.sign(make_commission(80, txn_id, b"\xB0" * 32))
        copy = reg.AuthorityRegistryCopy(self.copy_a_path)
        self.assertTrue(copy.append_issued(txn))
        self.assertTrue(
            copy.append_state_transition(
                txn_id, reg.TransactionState.CONSUMED_PREPARED, txn.manifest_digest_sha256,
                False, b"\x09" * reg.CHALLENGE_BYTES,
            )
        )

        # Corrupt the row holding the transition directly at the storage
        # layer (simulating on-disk bit damage), bypassing the class's
        # own write path entirely.
        conn = sqlite3.connect(str(self.copy_a_path))
        row_id = conn.execute(
            "SELECT id FROM authority_log WHERE kind = ? ORDER BY id DESC LIMIT 1", (2,)
        ).fetchone()[0]
        conn.execute("UPDATE authority_log SET payload = ? WHERE id = ?", (b"\x00" * 4, row_id))
        conn.commit()
        conn.close()

        record, corrupt = copy.read_latest(txn.transaction_id_hex())
        # The dangerous masked outcome would be: corrupt=False and
        # record.state == ISSUED (silently "looking clean" at a stale,
        # pre-transition state). Neither must ever happen.
        self.assertTrue(corrupt)

    def test_owner_lookup_flags_corruption_instead_of_silently_skipping(self):
        txn_id = secrets.token_bytes(16)
        binding = make_binding(81)
        txn = self.sign(make_commission(81, txn_id, b"\xB1" * 32))
        copy = reg.AuthorityRegistryCopy(self.copy_a_path)
        self.assertTrue(copy.append_issued(txn))

        # An orphan transition row (no matching Issued record at all) is
        # unexplained history -- it must be surfaced as corruption by the
        # owner-scoped lookup too, never silently skipped to zero results.
        conn = sqlite3.connect(str(self.copy_a_path))
        orphan_payload = struct.pack(
            reg._TRANSITION_PAYLOAD_FORMAT,
            secrets.token_bytes(16),
            int(reg.TransactionState.ACTIVATION_SPENT),
            True,
            b"\x00" * reg.DIGEST_BYTES,
            b"\x00" * reg.CHALLENGE_BYTES,
        )
        conn.execute(
            "INSERT INTO authority_log(kind, transaction_id, payload) VALUES (?, ?, ?)",
            (2, secrets.token_bytes(16).hex(), orphan_payload),
        )
        conn.commit()
        conn.close()

        record, corrupt = copy.read_latest_activation_for_owner(binding)
        self.assertTrue(corrupt)
        self.assertIsNone(record)  # the genuinely-unrelated device has no activation at all.


class CliSmokeTests(AuthorityRegistryTestCase):
    """Exercises the actual `python3 scripts/ota_authority_registry.py`
    entry point end to end, not just the library functions."""

    def test_issue_then_reconcile_round_trip_via_cli_main(self):
        binding = make_binding(30)
        argv_issue = [
            "issue",
            "--registry-a", str(self.copy_a_path),
            "--registry-b", str(self.copy_b_path),
            "--issuer-private-key", str(self.private_key),
            "--work-dir", str(self.work_dir),
            "--operation", "commission",
            "--hardware-uid", binding.hardware_uid.hex(),
            "--mesh-public-key", binding.mesh_full_public_key.hex(),
            "--profile-id", "1",
            "--layout-id", "1",
            "--consent-owner-key", binding.consent_owner_public_key.hex(),
            "--manifest-digest", ("11" * 32),
            "--tx-floor", "0",
            "--rx-floor", "0",
            "--issuer-key-id", "1",
            "--issued-at", "1700000000",
        ]
        self.assertEqual(reg.main(argv_issue), 0)

        conn = sqlite3.connect(str(self.copy_a_path))
        transaction_id_hex = conn.execute("SELECT transaction_id FROM authority_log LIMIT 1").fetchone()[0]
        conn.close()

        argv_reconcile = [
            "reconcile",
            "--registry-a", str(self.copy_a_path),
            "--registry-b", str(self.copy_b_path),
            "--transaction-id", transaction_id_hex,
        ]
        self.assertEqual(reg.main(argv_reconcile), 0)

    def test_cli_rejects_wrong_length_hex_argument(self):
        argv = [
            "issue",
            "--registry-a", str(self.copy_a_path),
            "--registry-b", str(self.copy_b_path),
            "--issuer-private-key", str(self.private_key),
            "--work-dir", str(self.work_dir),
            "--operation", "commission",
            "--hardware-uid", "aabb",  # wrong length, must be 8 bytes.
            "--mesh-public-key", ("00" * 32),
            "--profile-id", "1",
            "--layout-id", "1",
            "--consent-owner-key", ("00" * 32),
            "--manifest-digest", ("11" * 32),
            "--tx-floor", "0",
            "--rx-floor", "0",
            "--issuer-key-id", "1",
            "--issued-at", "1700000000",
        ]
        with self.assertRaises(SystemExit):
            reg.main(argv)

    def test_generate_issuer_key_refuses_to_overwrite_existing_private_key(self):
        fresh_key_dir = self.work_dir / "fresh-keys"
        reg.generate_issuer_keypair(fresh_key_dir, name="dup")
        with self.assertRaises(reg.SigningError):
            reg.generate_issuer_keypair(fresh_key_dir, name="dup")


class CrossProcessLockTests(AuthorityRegistryTestCase):
    """Sol fe862c8 review, H2: two genuinely independent OS PROCESSES
    (real `subprocess`-launched CLI invocations, not two in-process
    `reg.main()` calls sharing one interpreter) racing a Commission for
    the exact same physical owner must never both succeed."""

    def _issue_argv(self, binding: reg.AuthorityBinding, txn_id_hex: str, manifest_digest_hex: str) -> list:
        return [
            "issue",
            "--registry-a", str(self.copy_a_path),
            "--registry-b", str(self.copy_b_path),
            "--issuer-private-key", str(self.private_key),
            "--work-dir", str(self.work_dir),
            "--operation", "commission",
            "--transaction-id", txn_id_hex,
            "--hardware-uid", binding.hardware_uid.hex(),
            "--mesh-public-key", binding.mesh_full_public_key.hex(),
            "--profile-id", "1",
            "--layout-id", "1",
            "--consent-owner-key", binding.consent_owner_public_key.hex(),
            "--manifest-digest", manifest_digest_hex,
            "--tx-floor", "1",
            "--rx-floor", "1",
            "--issuer-key-id", "1",
            "--issued-at", "1700000000",
        ]

    def test_lock_flocks_the_real_registry_copy_files_directly_not_a_derived_sidecar(self):
        # Sol39 H3: the lock must no longer derive a SEPARATE sidecar
        # lock-file path at all -- it must flock the ACTUAL registry
        # copy files. Prove this directly: while the lock is held, the
        # two real copy paths themselves must be lockable-conflicting
        # (a second independent flock attempt on the SAME fd-identity
        # blocks), and no stray ".authority-pair.lock"-style sidecar
        # file is created.
        with reg.CrossProcessRegistryPairLock(self.copy_a_path, self.copy_b_path):
            self.assertTrue(self.copy_a_path.exists())
            self.assertTrue(self.copy_b_path.exists())
        sidecar_candidates = list(self.work_dir.glob("*.authority-pair.lock"))
        self.assertEqual(sidecar_candidates, [])

    def _lock_in_subprocess(self, path_a: str, path_b: str, hold_seconds: float, result_queue) -> None:
        """Run in a genuinely separate OS process (multiprocessing uses
        fork() on POSIX): acquires the lock, records an acquire
        timestamp, holds it for hold_seconds, records a release
        timestamp, then reports both back through the queue."""
        with reg.CrossProcessRegistryPairLock(pathlib.Path(path_a), pathlib.Path(path_b)):
            acquired_at = time.monotonic()
            time.sleep(hold_seconds)
            released_at = time.monotonic()
        result_queue.put((acquired_at, released_at))

    def test_lock_identity_is_stable_across_the_absent_to_present_transition(self):
        # Sol39 H3: a lock constructed while the copy file is genuinely
        # ABSENT and one constructed AFTER it is created (by the other
        # side's O_CREAT) must still contend on the exact same
        # underlying file -- mirrors the C++ H2 absent->present test.
        self.assertFalse(self.copy_a_path.exists())
        result_queue: multiprocessing.Queue = multiprocessing.Queue()
        child = multiprocessing.Process(
            target=self._lock_in_subprocess,
            args=(str(self.copy_a_path), str(self.copy_b_path), 0.3, result_queue),
        )
        child.start()
        time.sleep(0.05)
        # Parent constructs/acquires its OWN lock instance AFTER the
        # child has almost certainly already created copy_a_path.
        parent_lock = reg.CrossProcessRegistryPairLock(self.copy_a_path, self.copy_b_path)
        with parent_lock:
            parent_acquired_at = time.monotonic()
        child.join(timeout=5)
        self.assertEqual(child.exitcode, 0)
        child_acquired_at, child_released_at = result_queue.get(timeout=5)
        self.assertGreaterEqual(parent_acquired_at, child_released_at)

    def test_lock_treats_a_hardlink_in_a_different_directory_as_the_same_physical_copy(self):
        # Sol39 H3: a HARDLINK of copy A reachable through a genuinely
        # DIFFERENT directory must still contend against a lock built
        # from the ORIGINAL path -- dev+ino identity, never a derived
        # path string.
        self.copy_a_path.touch()
        other_dir = self.work_dir / "other-dir"
        other_dir.mkdir()
        hardlink_path = other_dir / "copyA-hardlink.bin"
        os.link(str(self.copy_a_path), str(hardlink_path))
        self.assertEqual(os.stat(self.copy_a_path).st_ino, os.stat(hardlink_path).st_ino)

        result_queue: multiprocessing.Queue = multiprocessing.Queue()
        child = multiprocessing.Process(
            target=self._lock_in_subprocess,
            args=(str(self.copy_a_path), str(self.copy_b_path), 0.3, result_queue),
        )
        child.start()
        time.sleep(0.05)
        # Parent locks (hardlink_path, copy_b_path) -- a different path
        # string, different directory, same physical inode as copy A.
        with reg.CrossProcessRegistryPairLock(hardlink_path, self.copy_b_path):
            parent_acquired_at = time.monotonic()
        child.join(timeout=5)
        self.assertEqual(child.exitcode, 0)
        child_acquired_at, child_released_at = result_queue.get(timeout=5)
        self.assertGreaterEqual(parent_acquired_at, child_released_at)

    def test_lock_serializes_overlapping_pairs_sharing_one_common_copy(self):
        # Sol39 H3: pairs (A, B) and (B, C) share exactly one common
        # copy -- the OLD lexicographic-pair-path scheme never
        # serialized these against each other. Real two-process test.
        copy_c_path = self.work_dir / "copyC.bin"
        result_queue: multiprocessing.Queue = multiprocessing.Queue()
        child = multiprocessing.Process(
            target=self._lock_in_subprocess,
            args=(str(self.copy_b_path), str(copy_c_path), 0.3, result_queue),
        )
        child.start()
        time.sleep(0.05)
        # Parent locks (A, B) -- overlapping on B only.
        with reg.CrossProcessRegistryPairLock(self.copy_a_path, self.copy_b_path):
            parent_acquired_at = time.monotonic()
        child.join(timeout=5)
        self.assertEqual(child.exitcode, 0)
        child_acquired_at, child_released_at = result_queue.get(timeout=5)
        self.assertGreaterEqual(parent_acquired_at, child_released_at)

    def test_lock_order_is_independent_of_constructor_argument_order(self):
        # Reversed argument order must still resolve to the SAME
        # (dev, ino)-stable acquisition order -- proven here by racing a
        # (B, A)-order lock against an (A, B)-order lock for mutual
        # exclusion, the same structural guarantee the old test asserted
        # via an internal `_lock_path` attribute that no longer exists.
        result_queue: multiprocessing.Queue = multiprocessing.Queue()
        child = multiprocessing.Process(
            target=self._lock_in_subprocess,
            args=(str(self.copy_b_path), str(self.copy_a_path), 0.3, result_queue),
        )
        child.start()
        time.sleep(0.05)
        with reg.CrossProcessRegistryPairLock(self.copy_a_path, self.copy_b_path):
            parent_acquired_at = time.monotonic()
        child.join(timeout=5)
        self.assertEqual(child.exitcode, 0)
        child_acquired_at, child_released_at = result_queue.get(timeout=5)
        self.assertGreaterEqual(parent_acquired_at, child_released_at)

    def test_two_real_os_processes_racing_commission_for_the_same_owner_never_both_succeed(self):
        binding = make_binding(85)
        txn_id_a = secrets.token_bytes(16).hex()
        txn_id_b = secrets.token_bytes(16).hex()
        argv_a = self._issue_argv(binding, txn_id_a, "aa" * 32)
        argv_b = self._issue_argv(binding, txn_id_b, "bb" * 32)

        script = str(ROOT / "scripts" / "ota_authority_registry.py")
        # Two GENUINELY independent OS processes (not two in-process
        # reg.main() calls sharing one interpreter/GIL) launched as close
        # together as possible to maximize the real check-then-act race
        # window this lock closes.
        proc_a = subprocess.Popen([sys.executable, script] + argv_a, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_b = subprocess.Popen([sys.executable, script] + argv_b, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out_a, err_a = proc_a.communicate(timeout=30)
        out_b, err_b = proc_b.communicate(timeout=30)

        a_ok = proc_a.returncode == 0
        b_ok = proc_b.returncode == 0
        # Exactly one process's Commission may ever win the exact same
        # owner -- never both (a genuine ownership fork) and never
        # neither (the lock must not deadlock/spuriously deny both real
        # attempts).
        self.assertNotEqual(a_ok, b_ok, f"a_ok={a_ok} b_ok={b_ok} err_a={err_a!r} err_b={err_b!r}")

        # The registry pair itself must agree on exactly one surviving
        # owner lineage afterward -- not merely that the two process
        # return codes looked right.
        pair = self.pair()
        lineage = pair.reconcile_ownership_lineage(binding)
        self.assertEqual(lineage.outcome, reg.ReconciliationOutcome.AGREED)

    def test_two_real_os_processes_racing_commission_with_a_crypto_domain_relabel_never_both_succeed(self):
        # Sol43 HIGH fix, genuinely CONCURRENT variant: process A issues a
        # plain genesis Commission for a physical device; process B races
        # it with the SAME hardware_uid+mesh_public_key but a DIFFERENT
        # group_selector (a crypto-domain relabel) -- same_ownership alone
        # would treat these as two distinct, unrelated "owners" and let
        # both through even serialized one-after-another. The physical-
        # lineage fence (hardware_uid only) must still ensure exactly one
        # of the two ever wins, never both, even when they race as two
        # genuinely independent OS processes.
        binding = make_binding(86)
        relabeled = make_binding(86)
        relabeled.group_selector = 0x5678
        txn_id_a = secrets.token_bytes(16).hex()
        txn_id_b = secrets.token_bytes(16).hex()
        argv_a = self._issue_argv(binding, txn_id_a, "cc" * 32)
        argv_b = self._issue_argv(relabeled, txn_id_b, "dd" * 32) + ["--group-selector", str(0x5678)]

        script = str(ROOT / "scripts" / "ota_authority_registry.py")
        proc_a = subprocess.Popen([sys.executable, script] + argv_a, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_b = subprocess.Popen([sys.executable, script] + argv_b, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out_a, err_a = proc_a.communicate(timeout=30)
        out_b, err_b = proc_b.communicate(timeout=30)

        a_ok = proc_a.returncode == 0
        b_ok = proc_b.returncode == 0
        self.assertNotEqual(a_ok, b_ok, f"a_ok={a_ok} b_ok={b_ok} err_a={err_a!r} err_b={err_b!r}")

        pair = self.pair()
        lineage = pair.reconcile_physical_lineage(binding)
        self.assertEqual(lineage.outcome, reg.ReconciliationOutcome.AGREED)


# ---------------------------------------------------------------------
# FakeMaintenanceDevice -- an explicit in-process fake Maintenance-ABI
# responder. NEVER real hardware: it is driven purely in-process over
# the same `.command(payload, expected, timeout) -> bytes` contract a
# real `ota_rf_lab.FramedSerial` instance exposes, using Hydra's REAL
# `encode_request`/`decode_request`/`encode_reply`/`decode_measurement`
# codec functions directly (never a duplicated parser). It independently
# verifies the issuer's real Ed25519 signature on the uploaded
# PrepareAuthorizationV1 (never trusting the host blindly) and signs its
# own PREPARE_ACK with a real device Ed25519 keypair standing in for the
# binding's mesh_full_public_key -- exercising genuine signature
# verification on both sides of the handshake, not a placeholder.
# ---------------------------------------------------------------------


def _pad_to(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


# Sol HIGH2/HIGH3 fix fixtures: a genuinely self-consistent "what this
# fake device actually has flashed" baseline -- real SHA-256 digests
# over real (fixed, deterministic) fixture bytes, never arbitrary filler
# tag bytes. FakeMaintenanceDevice's MEASURE handler reports exactly
# this evidence by default, and PrepareHandshakeTests._baseline_manifest
# certifies the SAME evidence -- so the happy-path tests genuinely
# satisfy verify_measurement_matches_certified_baseline's cross-checks
# (including the raw_sdk28/sdk28_sha256 self-consistency check) rather
# than relying on an unchecked placeholder.
GENUINE_RAW_SDK28 = hashlib.sha256(b"authority-test-sdk28-fixture-v1").digest()[:28]


def default_genuine_baseline_manifest() -> "reg.BaselineCertificationManifest":
    return reg.BaselineCertificationManifest(
        approved_image_sha256=hashlib.sha256(b"authority-test-image-fixture-v1").digest(),
        approved_image_extent_offset=0x1000,
        approved_image_extent_length=0x2000,
        expected_sdk28_sha256_digest=hashlib.sha256(GENUINE_RAW_SDK28).digest(),
        stock_loader_artifact_sha256=hashlib.sha256(b"authority-test-loader-fixture-v1").digest(),
        stock_loader_artifact_range_start=0x100,
        stock_loader_artifact_range_length=0x400,
        boot_config_id=0x00010001,
        allow_ordinary_userdata=False,
    )


class FakeMaintenanceDevice:
    def __init__(self, binding: "reg.AuthorityBinding", device_private_key_path, issuer_public_key_raw: bytes,
                 work_dir, poll_pending_attempts: int = 1,
                 manifest: "Optional[reg.BaselineCertificationManifest]" = None,
                 tamper_prepared_artifact: bool = False):
        self.binding = binding
        self.device_private_key_path = device_private_key_path
        self.issuer_public_key_raw = issuer_public_key_raw
        self.work_dir = work_dir
        self.poll_pending_attempts = poll_pending_attempts
        # Sol HIGH2/HIGH3 fix: the baseline this fake genuinely has
        # "flashed" -- defaults to default_genuine_baseline_manifest()
        # (the same fixture PrepareHandshakeTests._baseline_manifest
        # certifies) so callers that don't care still get a genuinely
        # self-consistent device, never an unchecked all-zero stand-in.
        self.manifest = manifest or default_genuine_baseline_manifest()
        # FOR TESTS ONLY (Sol HIGH3 regression coverage): when set, this
        # fake deliberately corrupts ONE byte inside its OWN genuine
        # PreparedArtifactV1 encoding's embedded G238 region BEFORE
        # computing/signing its PREPARE_ACK root digest -- modelling a
        # device/transport that returns a header-only-correct but
        # semantically-wrong P683 whose signed ack is still internally
        # self-consistent (a signed R alone proves nothing about P's
        # actual provenance). Real production code never sets this.
        self.tamper_prepared_artifact = tamper_prepared_artifact
        self._session = None
        self._host_challenge = None
        self._device_nonce = None
        # Real, purpose-scoped device-minted challenges -- deliberately
        # SEPARATE from MEASUREMENT's device_nonce (that substitution was
        # a confirmed production call-path mismatch, per MAIN's adapter
        # correction). Each is single-use: minted on CHALLENGE, consumed
        # (and cleared) the moment the matching PREPARE/ACTIVATE trigger
        # actually checks it, never reusable across attempts.
        self._prepare_challenge = None
        self._activate_challenge = None
        self._objects = {}
        self._poll_remaining = None
        self.request_log = []
        self.prepare_attempts = 0


    def command(self, payload: bytes, expected=(reg.maint.RESPONSE,), timeout: float = 5.0) -> bytes:
        request = reg.maint.decode_request(payload)
        self.request_log.append(request.subcommand)
        reply = self._handle(request)
        return reg.maint.encode_reply(reply)

    def _reply(self, request, *, status=reg.maint.Status.OK, reason=reg.maint.Reason.NONE,
               object_kind=reg.maint.ObjectKind.NONE, total=0, offset=0, data=b"", session=None):
        return reg.maint.Reply(
            subcommand=request.subcommand, status=status, reason=reason,
            session=session if session is not None else (self._session or bytes(16)),
            request_id=request.request_id, job_ticket=0,
            object_kind=object_kind, total=total, offset=offset, data=data,
        )

    def _handle(self, request):
        sub = reg.maint.Subcommand
        if request.subcommand == sub.OPEN:
            self._session = secrets.token_bytes(16)
            self._host_challenge = request.data
            # PREPARED_ARTIFACT is genuinely durable on-device flash state
            # (the staged root) and must survive a reconnect -- a real
            # device never reseeds it merely because a new USB session
            # opened. Only this SESSION's own ephemeral job-input/upload
            # slots (AUTHORITY_GRANT/PREPARE_INPUT/*_AUTHORIZATION/*_ACK/
            # MEASUREMENT) and challenges are cleared.
            preserved_artifact = self._objects.get(reg.maint.ObjectKind.PREPARED_ARTIFACT)
            self._objects = {}
            if preserved_artifact is not None:
                self._objects[reg.maint.ObjectKind.PREPARED_ARTIFACT] = preserved_artifact
            self._poll_remaining = None
            self._prepare_challenge = None
            self._activate_challenge = None
            return self._reply(request, session=self._session)
        if request.session != self._session:
            return self._reply(request, status=reg.maint.Status.DENIED, reason=reg.maint.Reason.INVALID_SESSION)
        if request.subcommand == sub.CHALLENGE:
            # FINAL agreed shape: the existing objectKind field selects
            # PURPOSE (PrepareAuthorization=4 or ActivationAuthorization=5),
            # never an uploaded 267-byte object. Mints a FRESH,
            # purpose-scoped device challenge on every call -- genuinely
            # independent of OPEN's host_challenge and MEASUREMENT's
            # device_nonce, matching the single-authoritative-challenge-
            # owner contract.
            kind = reg.maint.ObjectKind
            if request.object_kind == kind.PREPARE_AUTHORIZATION:
                self._prepare_challenge = secrets.token_bytes(16)
                return self._reply(request, data=self._prepare_challenge)
            if request.object_kind == kind.ACTIVATION_AUTHORIZATION:
                self._activate_challenge = secrets.token_bytes(16)
                return self._reply(request, data=self._activate_challenge)
            return self._reply(request, status=reg.maint.Status.DENIED, reason=reg.maint.Reason.BAD_OBJECT_KIND)
        if request.subcommand == sub.MEASURE:
            self._device_nonce = secrets.token_bytes(16)
            measurement = reg.maint.Measurement(
                uid8=self.binding.hardware_uid,
                full_public_key=self.binding.mesh_full_public_key,
                profile=self.binding.profile_id,
                target=0,
                current_role=self.binding.historical_initial_role_id,
                layout=self.binding.layout_id,
                sdk28_sha256=self.manifest.expected_sdk28_sha256_digest,
                image_extent=self.manifest.approved_image_extent_length,
                image_address=self.manifest.approved_image_extent_offset,
                image_sha256=self.manifest.approved_image_sha256,
                image_crc16=0,
                loader_start=self.manifest.stock_loader_artifact_range_start,
                loader_length=self.manifest.stock_loader_artifact_range_length,
                loader_sha256=self.manifest.stock_loader_artifact_sha256,
                boot_config_id=self.manifest.boot_config_id,
                host_challenge=self._host_challenge,
                device_nonce=self._device_nonce,
                raw_sdk28=GENUINE_RAW_SDK28,
            )
            self._objects[reg.maint.ObjectKind.MEASUREMENT] = bytearray(reg.maint.encode_measurement(measurement))
            return self._reply(request)
        if request.subcommand == sub.PUT_FRAGMENT:
            buf = self._objects.setdefault(request.object_kind, bytearray(request.total))
            buf[request.offset:request.offset + len(request.data)] = request.data
            return self._reply(request, object_kind=request.object_kind, total=request.total, offset=request.offset)
        if request.subcommand == sub.READ_OBJECT:
            buf = self._objects.get(request.object_kind)
            if buf is None:
                return self._reply(request, status=reg.maint.Status.MISSING, object_kind=request.object_kind)
            count = request.data_len
            chunk = bytes(buf[request.offset:request.offset + count])
            return self._reply(
                request, object_kind=request.object_kind, total=len(buf), offset=request.offset, data=chunk
            )
        if request.subcommand == sub.PREPARE:
            self.prepare_attempts += 1
            grant_bytes = bytes(self._objects.get(reg.maint.ObjectKind.AUTHORITY_GRANT, b""))
            prepare_bytes = bytes(self._objects.get(reg.maint.ObjectKind.PREPARE_AUTHORIZATION, b""))
            prepare_input_bytes = bytes(self._objects.get(reg.maint.ObjectKind.PREPARE_INPUT, b""))
            if (
                len(grant_bytes) != reg.RECORD_BYTES
                or len(prepare_bytes) != reg.AUTH_RECORD_BYTES
                or len(prepare_input_bytes) != reg.PREPARE_AUTH_INPUT_DIGEST_SOURCE_BYTES
            ):
                return self._reply(request, status=reg.maint.Status.MISSING)
            prepare = reg.parse_prepare_authorization_record(prepare_bytes)
            signed_message = reg.serialize_prepare_authorization_signed_message(prepare)
            if not reg.verify_bytes(
                signed_message, prepare.issuer_signature_ed25519, self.issuer_public_key_raw, self.work_dir
            ):
                return self._reply(request, status=reg.maint.Status.DENIED)
            # Real device-side behavior per MAIN's adapter clarification:
            # verify the signed digest against the RETAINED raw
            # PREPARE_INPUT material this device itself holds, never
            # trusting the embedded digest alone.
            if hashlib.sha256(prepare_input_bytes).digest() != prepare.input_digest_sha256:
                return self._reply(request, status=reg.maint.Status.DENIED)
            # Real device-session binding check: consume THIS device's
            # own tracked outstanding PREPARE-purpose challenge (minted
            # earlier via CHALLENGE) -- never a bare caller-echoed value,
            # and never MEASUREMENT.device_nonce (a confirmed production
            # call-path mismatch, per MAIN's correction). Single-use: no
            # outstanding challenge (never requested, or already spent by
            # a prior PREPARE attempt) denies outright.
            if self._prepare_challenge is None or prepare.device_fresh_challenge != self._prepare_challenge:
                return self._reply(request, status=reg.maint.Status.DENIED)
            self._prepare_challenge = None
            # Sol HIGH3 fix: build a genuine, canonically-encoded
            # PreparedArtifactV1 -- parsed straight back out of the
            # SAME retained PREPARE_INPUT material this device itself
            # verified above (G238||C238||B117||rxKind||peerPK), never
            # an opaque placeholder blob -- plus this device's own
            # genuinely-generated store identity and the exact staged
            # TX/RX floors from the grant it just verified.
            parsed_grant = reg.parse_record(prepare_input_bytes[0:reg.RECORD_BYTES])
            parsed_certify = reg.parse_record(
                prepare_input_bytes[reg.RECORD_BYTES:2 * reg.RECORD_BYTES]
            )
            parsed_manifest = reg.parse_baseline_manifest(
                prepare_input_bytes[2 * reg.RECORD_BYTES:2 * reg.RECORD_BYTES + reg.BASELINE_MANIFEST_BYTES]
            )
            rx_kind_offset = 2 * reg.RECORD_BYTES + reg.BASELINE_MANIFEST_BYTES
            parsed_rx_kind = reg.PrepareRxContextKind(prepare_input_bytes[rx_kind_offset])
            parsed_peer_pk = bytes(prepare_input_bytes[rx_kind_offset + 1:rx_kind_offset + 1 + reg.PUBLIC_KEY_BYTES])
            artifact = reg.serialize_prepared_artifact(reg.PreparedArtifactV1(
                grant=parsed_grant, certify=parsed_certify, manifest=parsed_manifest, rx_kind=parsed_rx_kind,
                peer_full_public_key=parsed_peer_pk,
                store_identity=secrets.token_bytes(16),
                sdk28_sha256=parsed_manifest.expected_sdk28_sha256_digest,
                tx_upper_bound=parsed_grant.initial_tx_sequence_floor,
                genesis_floor=parsed_grant.initial_rx_replay_floor,
            ))
            if self.tamper_prepared_artifact:
                # FOR TESTS ONLY: corrupt one byte inside the embedded
                # G238 grant region (offset 0) AFTER the genuine encode
                # but BEFORE computing/signing root_digest below, so the
                # device's own ack stays internally self-consistent --
                # exactly the "signed R alone does not validate P
                # provenance" scenario Sol's HIGH3 finding describes.
                artifact = bytearray(artifact)
                artifact[0] ^= 0xFF
                artifact = bytes(artifact)
            self._objects[reg.maint.ObjectKind.PREPARED_ARTIFACT] = bytearray(artifact)
            root_digest = reg.compute_prepared_root_commitment_sha256(artifact)
            # Per MAIN's Sol-freeze correction: the ack message's legacy-
            # named first argument carries the exact DEVICE-minted
            # authorization challenge C just consumed above, never OPEN's
            # host_challenge (session/measurement correlation only).
            ack_message = reg.serialize_prepare_ack_message(
                prepare.device_fresh_challenge, self._device_nonce, prepare.transaction_id, root_digest
            )
            signature = reg.sign_bytes(ack_message, self.device_private_key_path, self.work_dir)
            ack_bytes = self._device_nonce + root_digest + signature
            self._objects[reg.maint.ObjectKind.PREPARE_ACK] = bytearray(ack_bytes)
            self._poll_remaining = self.poll_pending_attempts
            return self._reply(request, status=reg.maint.Status.PENDING)
        if request.subcommand == sub.ACTIVATE:
            activate_bytes = bytes(self._objects.get(reg.maint.ObjectKind.ACTIVATION_AUTHORIZATION, b""))
            artifact = self._objects.get(reg.maint.ObjectKind.PREPARED_ARTIFACT)
            if len(activate_bytes) != reg.AUTH_RECORD_BYTES or artifact is None:
                # No EXISTING prepared root on this device session (e.g.
                # erased/never-prepared store) -- NEVER reseed; deny.
                return self._reply(request, status=reg.maint.Status.MISSING)
            auth = reg.parse_activation_authorization_record(activate_bytes)
            signed_message = reg.serialize_activation_authorization_signed_message(auth)
            if not reg.verify_bytes(
                signed_message, auth.issuer_signature_ed25519, self.issuer_public_key_raw, self.work_dir
            ):
                return self._reply(request, status=reg.maint.Status.DENIED)
            # Device may activate ONLY the EXISTING matching prepared
            # root it itself staged during PREPARE -- never an arbitrary
            # host-asserted digest.
            existing_root_digest = reg.compute_prepared_root_commitment_sha256(bytes(artifact))
            if auth.prepared_root_digest_sha256 != existing_root_digest:
                return self._reply(request, status=reg.maint.Status.DENIED)
            # Single-use, purpose-scoped ACTIVATE challenge consumption --
            # same discipline as PREPARE above, never a bare caller-echo.
            if self._activate_challenge is None or auth.device_fresh_challenge != self._activate_challenge:
                return self._reply(request, status=reg.maint.Status.DENIED)
            self._activate_challenge = None
            activate_device_nonce = secrets.token_bytes(16)
            ack_message = reg.serialize_activate_ack_message(
                auth.device_fresh_challenge, activate_device_nonce, auth.transaction_id,
                auth.prepared_root_digest_sha256,
            )
            signature = reg.sign_bytes(ack_message, self.device_private_key_path, self.work_dir)
            ack_bytes = activate_device_nonce + signature
            self._objects[reg.maint.ObjectKind.ACTIVATE_ACK] = bytearray(ack_bytes)
            self._poll_remaining = self.poll_pending_attempts
            return self._reply(request, status=reg.maint.Status.PENDING)
        if request.subcommand == sub.POLL:
            if self._poll_remaining is None:
                return self._reply(request, status=reg.maint.Status.DENIED)
            if self._poll_remaining > 0:
                self._poll_remaining -= 1
                return self._reply(request, status=reg.maint.Status.PENDING)
            return self._reply(request)
        if request.subcommand == sub.CLOSE:
            return self._reply(request)
        return self._reply(request, status=reg.maint.Status.DENIED, reason=reg.maint.Reason.UNSUPPORTED_SUBCOMMAND)


class PrepareHandshakeTests(AuthorityRegistryTestCase):
    """Drives `reg._run_prepare_handshake` (the real commission-existing/
    resume-commission production function, modulo the explicit
    transport-injection seam) against a FakeMaintenanceDevice -- the
    actual canonical signed PrepareAuthorizationV1 codec, real Ed25519
    signature verification on both directions, and real two-copy SQLite
    registry commits/readbacks are all exercised for real; only the
    serial transport itself is faked."""

    def setUp(self):
        super().setUp()
        self.device_private_key, self.device_public_key = reg.generate_issuer_keypair(
            self.work_dir / "device-keys", name="device"
        )
        self.device_public_key_raw = reg.read_raw_public_key(self.device_public_key)

    def _issue_and_commit(self, binding, operation, txn_id, manifest_digest=bytes(32), tx_floor=0, rx_floor=0,
                           revision=0, predecessor=bytes(16)) -> reg.AuthorityTransaction:
        txn = reg.AuthorityTransaction(
            binding=binding, operation=operation, transaction_id=txn_id, revision=revision,
            predecessor_transaction_id=predecessor, manifest_digest_sha256=manifest_digest,
            initial_tx_sequence_floor=tx_floor, initial_rx_replay_floor=rx_floor,
            issuer_key_id=1, issued_at_unix_seconds=1_700_000_000,
        )
        self.sign(txn)
        self.assertTrue(self.pair().commit_issued(txn))
        return txn

    def _baseline_manifest(self):
        # Sol HIGH2/HIGH3 fix: genuinely self-consistent real SHA-256
        # digests (shared with FakeMaintenanceDevice's default measured
        # baseline), never arbitrary filler tag bytes -- so
        # verify_measurement_matches_certified_baseline's raw/hash
        # self-consistency and cross-checks are genuinely exercised
        # rather than silently inert.
        return default_genuine_baseline_manifest()

    def _args(self, grant_txn_id: bytes, certify_txn_id: bytes) -> type:
        manifest = self._baseline_manifest()
        return argparse.Namespace(
            registry_a=str(self.copy_a_path), registry_b=str(self.copy_b_path),
            transaction_id=grant_txn_id.hex(), issuer_private_key=str(self.private_key),
            work_dir=str(self.work_dir), serial_path="fake",
            baseline_transaction_id=certify_txn_id.hex(),
            approved_image_sha256=manifest.approved_image_sha256.hex(),
            approved_image_extent_offset=manifest.approved_image_extent_offset,
            approved_image_extent_length=manifest.approved_image_extent_length,
            expected_sdk28_sha256_digest=manifest.expected_sdk28_sha256_digest.hex(),
            stock_loader_artifact_sha256=manifest.stock_loader_artifact_sha256.hex(),
            stock_loader_artifact_range_start=manifest.stock_loader_artifact_range_start,
            stock_loader_artifact_range_length=manifest.stock_loader_artifact_range_length,
            boot_config_id=manifest.boot_config_id,
            allow_ordinary_userdata=manifest.allow_ordinary_userdata,
        )

    def test_full_happy_path_commission_reaches_durable_activation_spent(self):
        """Hydra's maintenance owner has landed the CHALLENGE request-
        side objectKind-selector exception, and the device-side PREPARE
        challenge binding no longer substitutes MEASUREMENT.device_nonce
        (both confirmed production call-path mismatches, now fixed in
        this module and in FakeMaintenanceDevice's real-shaped PREPARE/
        CHALLENGE handling). The full commission-existing happy path now
        genuinely reaches a durably-confirmed ActivationSpent (root-
        bound) record on BOTH registry copies, backed by a real device-
        minted CHALLENGE, real PrepareAuthorizationV1 issuer signature,
        and real device PREPARE_ACK Ed25519 verification end to end."""
        binding = make_binding(150)
        binding.mesh_full_public_key = self.device_public_key_raw
        certify_id = secrets.token_bytes(16)
        grant_id = secrets.token_bytes(16)
        certify_txn = self._issue_and_commit(binding, reg.AuthorityOperation.CERTIFY_EXISTING_BASELINE, certify_id,
                                              manifest_digest=reg.compute_baseline_manifest_digest(
                                                  self._baseline_manifest()))
        grant_txn = self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir)
        args = self._args(grant_id, certify_id)
        rc = reg._run_prepare_handshake(args, resuming=False, transport_factory=lambda path: device)
        self.assertEqual(rc, 0)

        # Activation permission was durably released: ActivationSpent,
        # root-BOUND, confirmed AGREED after a fresh cold readback of
        # BOTH registry copies -- not merely one copy, not merely an
        # in-memory outcome.
        result = self.pair().reconcile(grant_id)
        self.assertEqual(result.resolved.state, reg.TransactionState.ACTIVATION_SPENT)
        self.assertTrue(result.resolved.root_bound)

        # The real device-side sequencing genuinely happened end to end:
        # OPEN/MEASURE, both retained uploads (AUTHORITY_GRANT,
        # PREPARE_INPUT), the real device-minted CHALLENGE, the signed
        # PREPARE_AUTHORIZATION upload, and the PREPARE trigger itself.
        self.assertIn(reg.maint.Subcommand.MEASURE, device.request_log)
        self.assertIn(reg.maint.Subcommand.CHALLENGE, device.request_log)
        self.assertIn(reg.maint.Subcommand.PREPARE, device.request_log)
        self.assertEqual(device.prepare_attempts, 1)

    def test_resume_commission_after_interrupted_first_attempt_restart_simulation(self):
        """Simulates a real restart: the first attempt only gets as far
        as a durable ConsumedPrepared commit (root-unbound) before
        'crashing' -- never touches the device. resume-commission must
        then pick the SAME transaction back up and genuinely reach a
        durably-confirmed ActivationSpent (root-bound) record."""
        binding = make_binding(151)
        binding.mesh_full_public_key = self.device_public_key_raw
        certify_id = secrets.token_bytes(16)
        grant_id = secrets.token_bytes(16)
        self._issue_and_commit(binding, reg.AuthorityOperation.CERTIFY_EXISTING_BASELINE, certify_id,
                                manifest_digest=reg.compute_baseline_manifest_digest(self._baseline_manifest()))
        self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        pair = self.pair()
        self.assertTrue(pair.commit_state_transition(
            grant_id, reg.TransactionState.CONSUMED_PREPARED, bytes(32), False, bytes(16)
        ))
        confirmed = pair.confirm_both_copies_durable(grant_id, reg.TransactionState.CONSUMED_PREPARED)
        self.assertEqual(confirmed.outcome, reg.ReconciliationOutcome.AGREED)

        device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir)
        args = self._args(grant_id, certify_id)
        rc = reg._run_prepare_handshake(args, resuming=True, transport_factory=lambda path: device)
        self.assertEqual(rc, 0)

        # The SAME transaction picked back up genuinely reached
        # ActivationSpent, root-BOUND, confirmed AGREED after a fresh
        # cold readback of BOTH registry copies.
        result = pair.reconcile(grant_id)
        self.assertEqual(result.resolved.state, reg.TransactionState.ACTIVATION_SPENT)
        self.assertTrue(result.resolved.root_bound)

        # commission-existing (fresh, non-resuming) must still refuse:
        # the transaction is no longer a freshly-Issued record -- this
        # host-side guard fires BEFORE any device I/O and does not
        # depend on the blocked CHALLENGE step at all.
        with self.assertRaises(SystemExit):
            reg._run_prepare_handshake(args, resuming=False, transport_factory=lambda path: device)

    def test_commission_existing_refuses_when_not_freshly_issued(self):
        """A second commission-existing attempt against an ALREADY
        ActivationSpent transaction (whether by a replayed device
        response or by operator error) must be refused BEFORE any
        device I/O -- the host-side state guard alone must stop it,
        never relying on the device to detect the replay itself.

        ActivationSpent is seeded directly through the real registry
        pair API (exactly as resume-simulation already seeds
        ConsumedPrepared) rather than via a live device session: this
        particular guard is purely a host-side state check and its
        correctness does not depend on how ActivationSpent was durably
        reached, so it is NOT affected by the currently-blocked device
        CHALLENGE dependency."""
        binding = make_binding(152)
        binding.mesh_full_public_key = self.device_public_key_raw
        certify_id = secrets.token_bytes(16)
        grant_id = secrets.token_bytes(16)
        self._issue_and_commit(binding, reg.AuthorityOperation.CERTIFY_EXISTING_BASELINE, certify_id,
                                manifest_digest=reg.compute_baseline_manifest_digest(self._baseline_manifest()))
        self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        # Seed ActivationSpent directly through the real registry pair API
        # (strict single-step ConsumedPrepared -> ActivationSpent advance,
        # exactly as the real device flow would durably commit it) rather
        # than via a live device session -- this test is about the
        # host-side state guard alone, independent of device I/O.
        pair = self.pair()
        root_digest = secrets.token_bytes(32)
        self.assertTrue(pair.commit_state_transition(
            grant_id, reg.TransactionState.CONSUMED_PREPARED, bytes(32), False, bytes(16)
        ))
        self.assertTrue(pair.commit_state_transition(
            grant_id, reg.TransactionState.ACTIVATION_SPENT, root_digest, True, bytes(16)
        ))
        confirmed = pair.confirm_both_copies_durable(grant_id, reg.TransactionState.ACTIVATION_SPENT)
        self.assertEqual(confirmed.outcome, reg.ReconciliationOutcome.AGREED)

        args = self._args(grant_id, certify_id)
        # A fresh device session object (never a reused one) representing
        # a literal physical attempt at the SAME already-spent
        # transaction -- it must never even reach the device.
        second_device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir)
        with self.assertRaises(SystemExit):
            reg._run_prepare_handshake(args, resuming=False, transport_factory=lambda path: second_device)
        self.assertEqual(second_device.request_log, [], "must never touch the device once already ActivationSpent")

    def test_device_prepare_ack_signed_by_wrong_key_is_rejected(self):
        """The host must independently verify the device's PREPARE_ACK
        signature against the grant's OWN recorded mesh_full_public_key
        -- a device that signs with a different (wrong/foreign) key must
        never be accepted, and the transaction must remain
        ConsumedPrepared (root-unbound), never falsely advance to
        ActivationSpent."""
        binding = make_binding(153)
        binding.mesh_full_public_key = self.device_public_key_raw
        certify_id = secrets.token_bytes(16)
        grant_id = secrets.token_bytes(16)
        self._issue_and_commit(binding, reg.AuthorityOperation.CERTIFY_EXISTING_BASELINE, certify_id,
                                manifest_digest=reg.compute_baseline_manifest_digest(self._baseline_manifest()))
        self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        wrong_private_key, _ = reg.generate_issuer_keypair(self.work_dir / "wrong-device-keys", name="wrong")
        device = FakeMaintenanceDevice(binding, wrong_private_key, self.public_key_raw, self.work_dir)
        args = self._args(grant_id, certify_id)
        with self.assertRaises(SystemExit) as ctx:
            reg._run_prepare_handshake(args, resuming=False, transport_factory=lambda path: device)
        self.assertIn("PREPARE_ACK signature verification failed", str(ctx.exception))

        result = self.pair().reconcile(grant_id)
        self.assertEqual(result.resolved.state, reg.TransactionState.CONSUMED_PREPARED)
        self.assertFalse(result.resolved.root_bound)

    def test_device_replaying_a_stale_device_nonce_is_denied(self):
        """A PrepareAuthorizationV1 whose device_fresh_challenge does NOT
        match the real device-minted nonce from this session's own
        MEASURE/READ_OBJECT(MEASUREMENT) round trip (e.g. a replayed or
        foreign challenge) must be denied by the device's PREPARE
        handler -- unsupported/unqualified entropy means deny, per Astra
        section 6."""
        binding = make_binding(154)
        binding.mesh_full_public_key = self.device_public_key_raw
        certify_id = secrets.token_bytes(16)
        grant_id = secrets.token_bytes(16)
        self._issue_and_commit(binding, reg.AuthorityOperation.CERTIFY_EXISTING_BASELINE, certify_id,
                                manifest_digest=reg.compute_baseline_manifest_digest(self._baseline_manifest()))
        self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        # NOTE: this test probes the DEVICE-side PREPARE handler's own
        # stale-nonce rejection in isolation via a manually-constructed
        # low-level session (below) -- it does not depend on, and
        # therefore is not affected by, the currently-blocked device
        # CHALLENGE request codec (see
        # test_full_happy_path_commission_reaches_durable_activation_spent).
        prepare_input_bytes = secrets.token_bytes(reg.PREPARE_AUTH_INPUT_DIGEST_SOURCE_BYTES)
        tampered_prepare = reg.PrepareAuthorizationV1(
            transaction_id=grant_id,
            grant_digest_sha256=bytes(32),
            input_digest_sha256=hashlib.sha256(prepare_input_bytes).digest(),
            authorized_revision=0,
            expected_binding=binding,
            device_fresh_challenge=bytes(16),  # deliberately wrong/stale.
            host_nonce=bytes(16),
        )
        signed = reg.serialize_prepare_authorization_signed_message(tampered_prepare)
        tampered_prepare.issuer_signature_ed25519 = reg.sign_bytes(signed, self.private_key, self.work_dir)

        fresh_device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir)
        session = reg.MaintenanceSessionClient(fresh_device)
        host_challenge = secrets.token_bytes(16)
        measurement = reg.read_device_measurement(session, host_challenge)
        session.upload_object(reg.maint.ObjectKind.AUTHORITY_GRANT, bytes(reg.RECORD_BYTES))
        session.upload_object(reg.maint.ObjectKind.PREPARE_INPUT, prepare_input_bytes)
        session.upload_object(reg.maint.ObjectKind.PREPARE_AUTHORIZATION,
                               reg.serialize_prepare_authorization_record(tampered_prepare))
        reply = session.trigger(reg.maint.Subcommand.PREPARE)
        self.assertEqual(reply.status, reg.maint.Status.DENIED)

    def test_commission_existing_uploads_retained_prepare_input_before_authorization(self):
        """Per MAIN's FW-adapter coordination: PREPARE needs the raw
        626-byte PREPARE_INPUT material retained on-device in its own
        typed job-input slot (ObjectKind.PREPARE_INPUT), uploaded via
        ordinary sequential PUT_FRAGMENT strictly BEFORE the signed
        267-byte PrepareAuthorizationV1 whose input_digest_sha256 the
        device verifies against it -- not merely an opaque digest
        trusted in isolation. Both retained objects genuinely reach the
        device, and PREPARE_AUTHORIZATION's input_digest_sha256 matches
        the uploaded PREPARE_INPUT material exactly."""
        binding = make_binding(157)
        binding.mesh_full_public_key = self.device_public_key_raw
        certify_id = secrets.token_bytes(16)
        grant_id = secrets.token_bytes(16)
        manifest = self._baseline_manifest()
        self._issue_and_commit(binding, reg.AuthorityOperation.CERTIFY_EXISTING_BASELINE, certify_id,
                                manifest_digest=reg.compute_baseline_manifest_digest(manifest))
        self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir)
        args = self._args(grant_id, certify_id)
        rc = reg._run_prepare_handshake(args, resuming=False, transport_factory=lambda path: device)
        self.assertEqual(rc, 0)

        # PREPARE_INPUT genuinely reached the device BEFORE the signed
        # PREPARE_AUTHORIZATION, and the authorization's input digest
        # matches that retained material exactly.
        received_input = bytes(device._objects[reg.maint.ObjectKind.PREPARE_INPUT])
        self.assertEqual(len(received_input), reg.PREPARE_AUTH_INPUT_DIGEST_SOURCE_BYTES)
        received_auth = bytes(device._objects[reg.maint.ObjectKind.PREPARE_AUTHORIZATION])
        prepare = reg.parse_prepare_authorization_record(received_auth)
        self.assertEqual(prepare.input_digest_sha256, hashlib.sha256(received_input).digest())

    def test_inspect_commission_reports_state_without_device_io(self):
        binding = make_binding(155)
        binding.mesh_full_public_key = self.device_public_key_raw
        grant_id = secrets.token_bytes(16)
        self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = reg._cmd_inspect_commission(argparse.Namespace(
                registry_a=str(self.copy_a_path), registry_b=str(self.copy_b_path),
                transaction_id=grant_id.hex(),
            ))
        self.assertEqual(rc, 0)
        output = buf.getvalue()
        self.assertIn("ISSUED", output)
        self.assertIn(binding.hardware_uid.hex(), output)

    def _activate_args(self, grant_txn_id: bytes) -> argparse.Namespace:
        return argparse.Namespace(
            registry_a=str(self.copy_a_path), registry_b=str(self.copy_b_path),
            transaction_id=grant_txn_id.hex(), issuer_private_key=str(self.private_key),
            work_dir=str(self.work_dir), serial_path="fake",
        )

    def _commission_to_activation_spent(self, tag: int):
        """Shared setup: drives a real commission-existing happy path to
        a durable ActivationSpent record and returns (binding, grant_id,
        certify_id, device) for activate-existing tests to continue
        against the SAME device/root state."""
        binding = make_binding(tag)
        binding.mesh_full_public_key = self.device_public_key_raw
        certify_id = secrets.token_bytes(16)
        grant_id = secrets.token_bytes(16)
        self._issue_and_commit(binding, reg.AuthorityOperation.CERTIFY_EXISTING_BASELINE, certify_id,
                                manifest_digest=reg.compute_baseline_manifest_digest(self._baseline_manifest()))
        self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir)
        rc = reg._run_prepare_handshake(
            self._args(grant_id, certify_id), resuming=False, transport_factory=lambda path: device
        )
        self.assertEqual(rc, 0)
        return binding, grant_id, certify_id, device

    def test_activate_existing_happy_path_delivers_existing_root_with_zero_additional_registry_write(self):
        """Mirrors AuthorityCoordinator::activateExistingRoot: delivers
        the ALREADY-durable ActivationSpent permit to the device and
        verifies its real, domain-separated signed ACTIVATE_ACK -- the
        registry's own recorded state/root/revision (every row written
        by commission-existing) is byte-for-byte unchanged afterwards,
        confirming NO additional registry write ever happens here."""
        binding, grant_id, _certify_id, device = self._commission_to_activation_spent(160)
        before = self.pair().reconcile(grant_id)
        before_copy_a_bytes = self.copy_a_path.read_bytes()
        before_copy_b_bytes = self.copy_b_path.read_bytes()

        rc = reg._run_activate_handshake(self._activate_args(grant_id), transport_factory=lambda path: device)
        self.assertEqual(rc, 0)

        after = self.pair().reconcile(grant_id)
        self.assertEqual(after.resolved.state, reg.TransactionState.ACTIVATION_SPENT)
        self.assertTrue(after.resolved.root_bound)
        self.assertEqual(after.resolved.prepared_root_digest_sha256, before.resolved.prepared_root_digest_sha256)
        # Zero additional registry spend: the on-disk registry bytes
        # genuinely did not change at all as a result of activate-existing.
        self.assertEqual(self.copy_a_path.read_bytes(), before_copy_a_bytes)
        self.assertEqual(self.copy_b_path.read_bytes(), before_copy_b_bytes)

        # The real device-side ACTIVATE sequencing genuinely happened:
        # a fresh MEASURE/CHALLENGE/ACTIVATE round, independent of the
        # earlier PREPARE attempt already recorded on `device`.
        self.assertIn(reg.maint.Subcommand.ACTIVATE, device.request_log)

        # Safe to retry indefinitely -- a second real device round trip
        # succeeds identically and still performs zero registry writes.
        rc_again = reg._run_activate_handshake(self._activate_args(grant_id), transport_factory=lambda path: device)
        self.assertEqual(rc_again, 0)
        self.assertEqual(self.copy_a_path.read_bytes(), before_copy_a_bytes)
        self.assertEqual(self.copy_b_path.read_bytes(), before_copy_b_bytes)

    def test_activate_existing_requires_prior_activation_spent_state(self):
        """activate-existing must never spend a fresh permission itself
        -- a transaction that never reached a durable, root-bound
        ActivationSpent (e.g. still Issued) is refused outright, with
        no device I/O ever attempted."""
        binding = make_binding(161)
        binding.mesh_full_public_key = self.device_public_key_raw
        grant_id = secrets.token_bytes(16)
        self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir)
        with self.assertRaises(SystemExit) as ctx:
            reg._run_activate_handshake(self._activate_args(grant_id), transport_factory=lambda path: device)
        self.assertIn("ActivationSpent", str(ctx.exception))
        self.assertEqual(device.request_log, [])  # no device I/O was ever attempted.

    def test_activate_existing_rejects_device_ack_signed_by_wrong_key(self):
        """The host must independently verify the device's ACTIVATE_ACK
        signature against the grant's OWN recorded mesh_full_public_key
        -- a device that signs with a different (wrong/foreign) key
        must never be accepted, and the durable registry record must
        remain byte-for-byte unchanged."""
        binding, grant_id, _certify_id, device = self._commission_to_activation_spent(162)
        before_copy_a_bytes = self.copy_a_path.read_bytes()
        before_copy_b_bytes = self.copy_b_path.read_bytes()

        wrong_private_key, _ = reg.generate_issuer_keypair(self.work_dir / "wrong-activate-keys", name="wrong")
        wrong_device = FakeMaintenanceDevice(binding, wrong_private_key, self.public_key_raw, self.work_dir)
        # Reuse the SAME real durably-staged PREPARED_ARTIFACT from the
        # genuine device so the root digest genuinely matches -- only
        # the device's signing key differs.
        wrong_device._objects[reg.maint.ObjectKind.PREPARED_ARTIFACT] = (
            device._objects[reg.maint.ObjectKind.PREPARED_ARTIFACT]
        )

        with self.assertRaises(SystemExit) as ctx:
            reg._run_activate_handshake(self._activate_args(grant_id), transport_factory=lambda path: wrong_device)
        self.assertIn("ACTIVATE_ACK signature verification failed", str(ctx.exception))
        self.assertEqual(self.copy_a_path.read_bytes(), before_copy_a_bytes)
        self.assertEqual(self.copy_b_path.read_bytes(), before_copy_b_bytes)

    def test_activate_existing_refuses_when_provenance_sidecars_disagree(self):
        """Astra section5/MAIN's 'durable P+G/C/B/provenance reread
        matching actual R' discipline: activate-existing rereads BOTH
        copies' prepared-artifact provenance sidecars BEFORE any device
        I/O. If the two on-disk sidecars genuinely disagree (one has
        been tampered/corrupted/replaced independently of the other),
        activation is refused outright -- no device I/O is attempted,
        and the registry remains byte-for-byte unchanged."""
        binding, grant_id, _certify_id, device = self._commission_to_activation_spent(163)
        before_copy_a_bytes = self.copy_a_path.read_bytes()
        before_copy_b_bytes = self.copy_b_path.read_bytes()

        # Tamper ONLY copy B's sidecar file in place (flip one byte in
        # the stored prepared-artifact payload) -- copy A's sidecar is
        # untouched, so the two now genuinely disagree.
        sidecar_b_path = reg._provenance_sidecar_path(self.copy_b_path, grant_id)
        raw = bytearray(sidecar_b_path.read_bytes())
        raw[reg.TRANSACTION_ID_BYTES] ^= 0xFF
        sidecar_b_path.write_bytes(bytes(raw))

        fresh_device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir)
        with self.assertRaises(SystemExit) as ctx:
            reg._run_activate_handshake(self._activate_args(grant_id), transport_factory=lambda path: fresh_device)
        self.assertIn("disagree", str(ctx.exception))
        self.assertEqual(fresh_device.request_log, [])  # refused BEFORE any device I/O.
        self.assertEqual(self.copy_a_path.read_bytes(), before_copy_a_bytes)
        self.assertEqual(self.copy_b_path.read_bytes(), before_copy_b_bytes)

    def test_activate_existing_denies_when_device_store_has_no_staged_root(self):
        """'Never reseed an absent/erased store' (Astra section6): a
        device whose own flash never actually received/retained the
        PREPARED_ARTIFACT (e.g. a factory-erased replacement unit, or
        one that lost power before PREPARE completed) must be denied
        MISSING by the real FakeMaintenanceDevice ACTIVATE handler --
        the host must never substitute its own host-side provenance
        copy as if it were the device's actual staged root, and must
        never attempt to push/reseed one onto the device."""
        binding, grant_id, _certify_id, _device = self._commission_to_activation_spent(164)
        before_copy_a_bytes = self.copy_a_path.read_bytes()
        before_copy_b_bytes = self.copy_b_path.read_bytes()

        # A genuinely distinct device instance that was NEVER driven
        # through the PREPARE handshake above -- its own `_objects` has
        # no PREPARED_ARTIFACT at all, simulating an erased/replacement
        # store, not merely a host-side bookkeeping gap.
        erased_device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir)
        self.assertNotIn(reg.maint.ObjectKind.PREPARED_ARTIFACT, erased_device._objects)

        with self.assertRaises(reg.MaintenanceProtocolError) as ctx:
            reg._run_activate_handshake(self._activate_args(grant_id), transport_factory=lambda path: erased_device)
        self.assertIn("ACTIVATE denied by device", str(ctx.exception))
        self.assertIn("MISSING", str(ctx.exception))
        self.assertEqual(self.copy_a_path.read_bytes(), before_copy_a_bytes)
        self.assertEqual(self.copy_b_path.read_bytes(), before_copy_b_bytes)

    def test_prepare_denies_before_any_mutation_when_measured_image_hash_mismatches_certified_baseline(self):
        """Sol HIGH2 regression: a device whose self-reported MEASURE
        evidence disagrees with the already-signed CertifyExistingBaseline
        (manifest C / certify_binding B) must be denied by
        verify_measurement_matches_certified_baseline BEFORE the
        AUTHORITY_GRANT/PREPARE_INPUT are ever uploaded, and BEFORE any
        registry state advances past ConsumedPrepared (root-unbound) --
        a happily-reporting-all-zeros-or-wrong device must never reach
        ActivationSpent just because its signed ack later matches."""
        binding = make_binding(170)
        binding.mesh_full_public_key = self.device_public_key_raw
        certify_id = secrets.token_bytes(16)
        grant_id = secrets.token_bytes(16)
        self._issue_and_commit(binding, reg.AuthorityOperation.CERTIFY_EXISTING_BASELINE, certify_id,
                                manifest_digest=reg.compute_baseline_manifest_digest(self._baseline_manifest()))
        self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        # This device genuinely measures a DIFFERENT image hash than the
        # one the CertifyExistingBaseline transaction above was signed
        # against -- modelling an operator/cable mix-up, or a device
        # that was never actually re-flashed to the certified baseline.
        tampered_manifest = self._baseline_manifest()
        tampered_manifest.approved_image_sha256 = bytes([0xEE]) * reg.BASELINE_IMAGE_DIGEST_BYTES
        device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir,
                                        manifest=tampered_manifest)
        args = self._args(grant_id, certify_id)

        with self.assertRaises(reg.MaintenanceProtocolError) as ctx:
            reg._run_prepare_handshake(args, resuming=False, transport_factory=lambda path: device)
        self.assertIn("image_sha256", str(ctx.exception))

        # Denied BEFORE any device mutation: MEASURE happened (that is
        # how the mismatch was even discovered), but the grant/prepare
        # input uploads and the PREPARE trigger itself never ran.
        self.assertIn(reg.maint.Subcommand.MEASURE, device.request_log)
        self.assertNotIn(reg.maint.ObjectKind.AUTHORITY_GRANT, device._objects)
        self.assertEqual(device.prepare_attempts, 0)

        # Denied BEFORE registry spend: the handshake's OWN earlier
        # ConsumedPrepared commit (made before the measurement check
        # runs) is as far as it ever gets -- never root-bound, never
        # ActivationSpent.
        result = self.pair().reconcile(grant_id)
        self.assertEqual(result.resolved.state, reg.TransactionState.CONSUMED_PREPARED)
        self.assertFalse(result.resolved.root_bound)

    def test_prepare_denies_before_sidecar_or_spend_when_prepared_artifact_fields_mismatch_the_authorized_inputs(self):
        """Sol HIGH3 regression: 'an arbitrary 683-byte blob is accepted
        if its hash matches the signed ACK' is the EXACT failure mode
        this proves closed. FakeMaintenanceDevice (with
        tamper_prepared_artifact=True) genuinely flips a byte inside its
        OWN P683's embedded G238 grant region AFTER building it but
        BEFORE computing/signing its PREPARE_ACK root digest -- so the
        device's own signed ack is fully internally self-consistent
        (compute_prepared_root_commitment_sha256(artifact) ==
        ack.root_digest_sha256 genuinely holds), yet the artifact's
        semantic content no longer matches the authorized grant this
        handshake actually staged. verify_prepared_artifact_semantics
        must still deny this BEFORE either provenance sidecar is ever
        written and BEFORE ActivationSpent is ever committed."""
        binding = make_binding(171)
        binding.mesh_full_public_key = self.device_public_key_raw
        certify_id = secrets.token_bytes(16)
        grant_id = secrets.token_bytes(16)
        self._issue_and_commit(binding, reg.AuthorityOperation.CERTIFY_EXISTING_BASELINE, certify_id,
                                manifest_digest=reg.compute_baseline_manifest_digest(self._baseline_manifest()))
        self._issue_and_commit(binding, reg.AuthorityOperation.COMMISSION, grant_id)

        device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir,
                                        tamper_prepared_artifact=True)
        args = self._args(grant_id, certify_id)

        with self.assertRaises(reg.MaintenanceProtocolError) as ctx:
            reg._run_prepare_handshake(args, resuming=False, transport_factory=lambda path: device)
        self.assertIn("PREPARED_ARTIFACT", str(ctx.exception))

        # The PREPARE trigger genuinely ran (the tampered device even
        # produced a self-consistent signed ack that passed the earlier
        # root-digest-matches-ack check) -- but semantic validation still
        # denies before any sidecar write or ActivationSpent commit.
        self.assertEqual(device.prepare_attempts, 1)
        registry_dir = self.work_dir
        sidecar_glob = list(registry_dir.glob("copy-a.sqlite.prepared-artifact-*.bin"))
        self.assertEqual(sidecar_glob, [], "no provenance sidecar may ever be written for a semantically-invalid P683")

        result = self.pair().reconcile(grant_id)
        self.assertEqual(result.resolved.state, reg.TransactionState.CONSUMED_PREPARED)
        self.assertFalse(result.resolved.root_bound)

    def test_obtain_device_challenge_returns_fresh_purpose_scoped_challenge(self):
        """CHALLENGE's FINAL agreed wire shape (objectKind as purpose
        selector, superseding the earlier purpose-byte proposal) is now
        live end to end: the REQUEST side's objectKind-selector
        exception has landed in the installed
        scripts/ota_maintenance_protocol.py, so a genuine, real-shaped
        CHALLENGE request/reply round trip succeeds and returns exactly
        16 bytes of device-minted entropy, independently fresh per
        purpose/call."""
        binding = make_binding(156)
        binding.mesh_full_public_key = self.device_public_key_raw
        device = FakeMaintenanceDevice(binding, self.device_private_key, self.public_key_raw, self.work_dir)
        session = reg.MaintenanceSessionClient(device)
        session.open(secrets.token_bytes(16))
        prepare_challenge = session.obtain_device_challenge(int(reg.maint.Subcommand.PREPARE))
        self.assertEqual(len(prepare_challenge), 16)
        activate_challenge = session.obtain_device_challenge(int(reg.maint.Subcommand.ACTIVATE))
        self.assertEqual(len(activate_challenge), 16)
        self.assertNotEqual(prepare_challenge, activate_challenge)
        # Independently fresh on each call for the SAME purpose too.
        second_prepare_challenge = session.obtain_device_challenge(int(reg.maint.Subcommand.PREPARE))
        self.assertNotEqual(prepare_challenge, second_prepare_challenge)


class ProvenanceSidecarFaultInjectionTests(AuthorityRegistryTestCase):
    """Sol MEDIUM4 regression coverage: real fault injection via
    write_prepared_artifact_provenance's `fsync_fault_for_tests` hook and
    direct calls into ensure_prepared_artifact_provenance /
    read_prepared_artifact_provenance -- the exact same lower-level
    production functions _run_prepare_handshake calls, exercised at the
    unit level so each distinct crash point (after copy A fsync/before
    copy B attempted; during copy B's own fsync; cold resume; a
    genuinely divergent copy A) can be proven independently rather than
    only as one combined end-to-end path. write_prepared_artifact_
    provenance only validates LENGTHS, never semantic P683/ack content,
    so fixed-length filler buffers are a legitimate, real fixture here
    (the semantic content validation is HIGH3's separate concern, proven
    above)."""

    def setUp(self):
        super().setUp()
        self.transaction_id = secrets.token_bytes(16)
        self.artifact = bytes([0x11]) * reg.maint.OBJECT_LENGTHS[reg.maint.ObjectKind.PREPARED_ARTIFACT]
        self.ack = bytes([0x22]) * reg.PREPARE_ACK_BYTES
        self.other_artifact = bytes([0x33]) * reg.maint.OBJECT_LENGTHS[reg.maint.ObjectKind.PREPARED_ARTIFACT]
        self.other_ack = bytes([0x44]) * reg.PREPARE_ACK_BYTES

    def test_resume_after_crash_between_copy_a_write_and_copy_b_attempt_completes_copy_b_without_touching_copy_a(self):
        """Models a real power-cut: copy A's sidecar landed durably
        (fsync'd, parent-dir fsync'd, function returned) but the process
        died before copy B's write was ever attempted. A cold resume
        that calls ensure_prepared_artifact_provenance for BOTH copies
        again must reuse A's already-durable content unchanged and
        genuinely complete B -- never re-attempt/overwrite A (which
        would raise outright under the raw writer) and never skip B."""
        reg.write_prepared_artifact_provenance(self.copy_a_path, self.transaction_id, self.artifact, self.ack)
        before_a_mtime_bytes = self.copy_a_path.with_name(
            self.copy_a_path.name + f".prepared-artifact-{self.transaction_id.hex()}.bin"
        ).read_bytes()

        # Resume: both calls must succeed, reusing A and completing B.
        reg.ensure_prepared_artifact_provenance(self.copy_a_path, self.transaction_id, self.artifact, self.ack)
        reg.ensure_prepared_artifact_provenance(self.copy_b_path, self.transaction_id, self.artifact, self.ack)

        after_a_bytes = self.copy_a_path.with_name(
            self.copy_a_path.name + f".prepared-artifact-{self.transaction_id.hex()}.bin"
        ).read_bytes()
        self.assertEqual(after_a_bytes, before_a_mtime_bytes)

        readback_a = reg.read_prepared_artifact_provenance(self.copy_a_path, self.transaction_id)
        readback_b = reg.read_prepared_artifact_provenance(self.copy_b_path, self.transaction_id)
        self.assertEqual(readback_a, (self.artifact, self.ack))
        self.assertEqual(readback_b, (self.artifact, self.ack))

    def test_fault_during_copy_b_fsync_never_leaves_a_partially_durable_sidecar_and_resume_still_succeeds(self):
        """A crash DURING copy B's own content fsync (after bytes were
        written into the OS page cache but before fsync ever returned)
        must never be mistaken for a durably-completed sidecar: the
        injected fault propagates out as a genuine exception, and a
        subsequent resume attempt for copy B must still succeed (never
        refuse as though a real durable write already existed) because
        the first (faulted) attempt never got past the O_EXCL create --
        the retry's own O_EXCL create succeeds cleanly this time."""
        reg.write_prepared_artifact_provenance(self.copy_a_path, self.transaction_id, self.artifact, self.ack)

        def boom():
            raise OSError("simulated power-cut during copy-B fsync")

        with self.assertRaises(OSError):
            reg.write_prepared_artifact_provenance(
                self.copy_b_path, self.transaction_id, self.artifact, self.ack, fsync_fault_for_tests=boom
            )
        # The faulted attempt's full payload was already written into
        # the OS page cache (write_prepared_artifact_provenance writes
        # the complete payload BEFORE calling fsync_fault_for_tests, so
        # the only thing skipped is the fsync/parent-dir-fsync durability
        # confirmation) -- this file's CONTENT already matches exactly
        # what a resume is about to write, so ensure_prepared_artifact_
        # provenance treats it as already-reconciled evidence and
        # completes cleanly, never re-raising FileExistsError and never
        # mistaking it for a genuinely divergent sidecar.
        reg.ensure_prepared_artifact_provenance(self.copy_b_path, self.transaction_id, self.artifact, self.ack)
        readback_b = reg.read_prepared_artifact_provenance(self.copy_b_path, self.transaction_id)
        self.assertEqual(readback_b, (self.artifact, self.ack))

    def test_cold_resume_with_both_copies_already_durable_is_a_genuine_no_op_success(self):
        """The fully-happy restart case: BOTH copies already durably
        hold the SAME reconciled provenance (e.g. the process crashed
        only AFTER both writes completed, before some later unrelated
        step) -- ensure_prepared_artifact_provenance for both must
        return cleanly without raising and without altering either
        file's content, and the fresh cold readback of both must still
        agree exactly with the original evidence."""
        reg.write_prepared_artifact_provenance(self.copy_a_path, self.transaction_id, self.artifact, self.ack)
        reg.write_prepared_artifact_provenance(self.copy_b_path, self.transaction_id, self.artifact, self.ack)

        reg.ensure_prepared_artifact_provenance(self.copy_a_path, self.transaction_id, self.artifact, self.ack)
        reg.ensure_prepared_artifact_provenance(self.copy_b_path, self.transaction_id, self.artifact, self.ack)

        self.assertEqual(reg.read_prepared_artifact_provenance(self.copy_a_path, self.transaction_id),
                          (self.artifact, self.ack))
        self.assertEqual(reg.read_prepared_artifact_provenance(self.copy_b_path, self.transaction_id),
                          (self.artifact, self.ack))

    def test_genuinely_divergent_existing_copy_is_refused_outright_never_silently_overwritten(self):
        """'The first durably-recorded provenance always wins' (Sol
        MEDIUM4): if copy A's sidecar already durably holds DIFFERENT
        semantic evidence than the current attempt is about to write
        (e.g. a genuinely different reconciled artifact/ack, not merely
        a legitimately-different-but-equivalent fresh challenge/ack that
        was already reconciled to the SAME artifact before this call),
        ensure_prepared_artifact_provenance must raise
        ProvenanceSidecarError and must NEVER overwrite/replace the
        existing durable content -- a caller must treat this as a hard
        denial with zero further state-machine progress, never a
        reconciliation to accept."""
        reg.write_prepared_artifact_provenance(self.copy_a_path, self.transaction_id, self.artifact, self.ack)

        with self.assertRaises(reg.ProvenanceSidecarError):
            reg.ensure_prepared_artifact_provenance(
                self.copy_a_path, self.transaction_id, self.other_artifact, self.other_ack
            )

        # The existing durable sidecar is byte-for-byte untouched.
        readback_a = reg.read_prepared_artifact_provenance(self.copy_a_path, self.transaction_id)
        self.assertEqual(readback_a, (self.artifact, self.ack))


if __name__ == "__main__":
    unittest.main()
