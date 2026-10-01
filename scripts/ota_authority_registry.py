#!/usr/bin/env python3
"""Host-side OTA commissioning authority: canonical transaction codec, a
real two-copy durable SQLite registry, and an operator CLI for signing
new Commission/Repair/Rekey transactions.

This is the OFFLINE half of the authority described in
src/ota/authority/*.h: it never talks to a device directly (no USB/
serial wiring here -- that is MAIN's later integration step) and it
never embeds a production registry path or issuer key anywhere in this
file. Every registry path and every private-key path is an explicit,
required operator argument; nothing is auto-created under the user's
home directory, and nothing here logs private-key material.

The wire layout below (AUTHORITY_SIGNED_MESSAGE_FORMAT /
AUTHORITY_RECORD_FORMAT) is byte-for-byte identical to
src/ota/authority/AuthorityCodec.h's serializeSignedMessage() /
serializeRecord() -- big-endian, bounded, no arrays growing without a
fixed field width. Keep the two in lockstep; a mismatch here would sign
bytes the device-side verifier disagrees about.
"""

import argparse
import binascii
import fcntl
import hashlib
import os
import secrets
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, List, Optional, Tuple

# Hydra (Maintenance-ABI owner) and the existing RF-lab FramedSerial
# transport both live alongside this file in scripts/ -- import directly
# (never duplicate their constants/parsing), mirroring how both modules'
# own test files resolve each other: insert THIS file's own directory
# first so `import ota_maintenance_protocol` / `import ota_rf_lab`
# resolve identically whether this script is run directly
# (`python3 scripts/ota_authority_registry.py ...`, where sys.path[0] is
# already `scripts/`) or imported from scripts/tests/ (which inserts the
# same directory before importing this module).
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ota_maintenance_protocol as maint  # noqa: E402
import ota_rf_lab  # noqa: E402  (FramedSerial transport only; never modified)

HARDWARE_UID_BYTES = 8
PUBLIC_KEY_BYTES = 32
DIGEST_BYTES = 32
TRANSACTION_ID_BYTES = 16
SIGNATURE_BYTES = 64
CHALLENGE_BYTES = 16


class CryptoDomainForm(IntEnum):
    PAIRWISE = 0xA1
    GROUP = 0xA2


class AuthorityOperation(IntEnum):
    COMMISSION = 1
    REPAIR = 2
    REKEY = 3
    CERTIFY_EXISTING_BASELINE = 4


class TransactionState(IntEnum):
    ISSUED = 1
    CONSUMED_PREPARED = 2
    ACTIVATION_SPENT = 3


_STATE_RANK = {
    TransactionState.ISSUED: 0,
    TransactionState.CONSUMED_PREPARED: 1,
    TransactionState.ACTIVATION_SPENT: 2,
}


class AuthorityCodecError(Exception):
    """Base class for every typed decode failure -- never caught broadly
    and never silently treated as a successful parse of zeroed fields."""


class RecordTooShort(AuthorityCodecError):
    pass


class RecordTooLong(AuthorityCodecError):
    pass


class InvalidOperation(AuthorityCodecError):
    pass


class InvalidCryptoForm(AuthorityCodecError):
    pass


class InvalidGroupSelectorForPairwise(AuthorityCodecError):
    pass


@dataclass
class AuthorityBinding:
    hardware_uid: bytes = bytes(HARDWARE_UID_BYTES)
    mesh_full_public_key: bytes = bytes(PUBLIC_KEY_BYTES)
    crypto_form: CryptoDomainForm = CryptoDomainForm.PAIRWISE
    group_selector: int = 0
    profile_id: int = 0
    layout_id: int = 0
    historical_initial_role_id: int = 0
    consent_owner_public_key: bytes = bytes(PUBLIC_KEY_BYTES)

    def same_ownership(self, other: "AuthorityBinding") -> bool:
        return (
            self.hardware_uid == other.hardware_uid
            and self.mesh_full_public_key == other.mesh_full_public_key
            and self.crypto_form == other.crypto_form
            and self.group_selector == other.group_selector
            and self.layout_id == other.layout_id
        )

    def same_device_identity(self, other: "AuthorityBinding") -> bool:
        """Same PHYSICAL device/domain/layout, deliberately WITHOUT
        comparing mesh_full_public_key -- mirrors
        AuthorityTypes.h::AuthorityBinding::sameDeviceIdentity exactly.
        Used only to find the prior history a genuine rekey (which
        changes the fullPK on purpose) is allowed to supersede."""
        return (
            self.hardware_uid == other.hardware_uid
            and self.crypto_form == other.crypto_form
            and self.group_selector == other.group_selector
            and self.layout_id == other.layout_id
        )

    def same_physical_lifetime(self, other: "AuthorityBinding") -> bool:
        """Sol43 HIGH fix: mirrors
        AuthorityTypes.h::AuthorityBinding::samePhysicalLifetime exactly.
        The LIFETIME first-use/fork-fence key is the full PHYSICAL
        hardware_uid ALONE -- the one field that is an immutable fact
        about the chip (nRF FICR DEVICEID), independent of changing
        mesh_full_public_key (rekey), historical_initial_role_id (role),
        profile_id, layout_id, OR crypto_form/group_selector
        (crypto-domain). Keeping crypto_form/group_selector in this key
        (as same_device_identity above still does) was itself the same
        kind of transport/label escape this fence exists to close: a
        second genuinely-signed Commission for the SAME hardware_uid but
        a different crypto-domain or layout must still be recognised as
        the SAME physical device's lifetime, never treated as an
        unrelated device's legitimate first commission."""
        return self.hardware_uid == other.hardware_uid


@dataclass
class AuthorityTransaction:
    binding: AuthorityBinding
    operation: AuthorityOperation
    transaction_id: bytes
    revision: int = 0
    predecessor_transaction_id: bytes = bytes(TRANSACTION_ID_BYTES)
    manifest_digest_sha256: bytes = bytes(DIGEST_BYTES)
    # Astra29 correction: this transaction carries NO issuer-precommitted
    # "expected root" field anymore (mirrors AuthorityTypes.h's removal of
    # expectedRootDigestSha256). The issuer cannot know the exact
    # prepared-store-root digest (R) ahead of time -- only the device/
    # store, after actually applying the manifest, can produce R (see
    # PreparedRootCommitment.h / R below). The prior field let a host-side
    # guard simply echo it back as if it were a real device-attested root
    # -- a confirmed "fake ACK R" defect; removing the field entirely
    # makes that shortcut structurally impossible.
    initial_tx_sequence_floor: int = 0
    initial_rx_replay_floor: int = 0
    issuer_key_id: int = 0
    issued_at_unix_seconds: int = 0
    issuer_signature_ed25519: bytes = bytes(SIGNATURE_BYTES)

    def transaction_id_hex(self) -> str:
        return self.transaction_id.hex()


def _require_len(name: str, value: bytes, expected: int) -> bytes:
    if len(value) != expected:
        raise ValueError(f"{name} must be exactly {expected} bytes, got {len(value)}")
    return value


# Python mirror of src/ota/authority/BaselineCertificationManifest.h --
# byte-for-byte identical canonical encoding (big-endian, fixed-width, 117
# bytes total), used ONLY as the digest embedded in a CertifyExistingBaseline
# transaction's manifest_digest_sha256 field. This does NOT change
# AUTHORITY_RECORD_FORMAT / RECORD_BYTES: that 238-byte wire format is
# shared by every operation.
BASELINE_IMAGE_DIGEST_BYTES = 32
BASELINE_STOCK_LOADER_DIGEST_BYTES = 32
# Tightened to match BaselineCertificationManifest.h: a full SHA-256
# digest of exact, frozen SDK identifier bytes, never a bare version int.
BASELINE_SDK_DIGEST_BYTES = 32

_BASELINE_MANIFEST_FORMAT = ">32sII32s32sIIIB"
BASELINE_MANIFEST_BYTES = struct.calcsize(_BASELINE_MANIFEST_FORMAT)
assert BASELINE_MANIFEST_BYTES == 117, BASELINE_MANIFEST_BYTES


@dataclass
class BaselineCertificationManifest:
    approved_image_sha256: bytes = bytes(BASELINE_IMAGE_DIGEST_BYTES)
    approved_image_extent_offset: int = 0
    approved_image_extent_length: int = 0
    expected_sdk28_sha256_digest: bytes = bytes(BASELINE_SDK_DIGEST_BYTES)
    stock_loader_artifact_sha256: bytes = bytes(BASELINE_STOCK_LOADER_DIGEST_BYTES)
    stock_loader_artifact_range_start: int = 0
    stock_loader_artifact_range_length: int = 0
    boot_config_id: int = 0
    allow_ordinary_userdata: bool = False


def serialize_baseline_manifest(manifest: BaselineCertificationManifest) -> bytes:
    return struct.pack(
        _BASELINE_MANIFEST_FORMAT,
        _require_len("approved_image_sha256", manifest.approved_image_sha256, BASELINE_IMAGE_DIGEST_BYTES),
        manifest.approved_image_extent_offset,
        manifest.approved_image_extent_length,
        _require_len(
            "expected_sdk28_sha256_digest", manifest.expected_sdk28_sha256_digest, BASELINE_SDK_DIGEST_BYTES
        ),
        _require_len(
            "stock_loader_artifact_sha256", manifest.stock_loader_artifact_sha256, BASELINE_STOCK_LOADER_DIGEST_BYTES
        ),
        manifest.stock_loader_artifact_range_start,
        manifest.stock_loader_artifact_range_length,
        manifest.boot_config_id,
        1 if manifest.allow_ordinary_userdata else 0,
    )


def parse_baseline_manifest(data: bytes) -> BaselineCertificationManifest:
    """Inverse of serialize_baseline_manifest -- fails closed (raises)
    on anything other than exactly BASELINE_MANIFEST_BYTES bytes; used
    by parse_prepared_artifact (Sol HIGH3) to decode the B117 region
    embedded in a PREPARED_ARTIFACT for cross-validation."""
    if len(data) != BASELINE_MANIFEST_BYTES:
        raise AuthorityCodecError(f"baseline manifest is {len(data)} bytes, need exactly {BASELINE_MANIFEST_BYTES}")
    (
        approved_image_sha256, extent_offset, extent_length, expected_sdk28_sha256_digest,
        stock_loader_artifact_sha256, loader_range_start, loader_range_length, boot_config_id, allow_flag,
    ) = struct.unpack(_BASELINE_MANIFEST_FORMAT, data)
    return BaselineCertificationManifest(
        approved_image_sha256=approved_image_sha256,
        approved_image_extent_offset=extent_offset,
        approved_image_extent_length=extent_length,
        expected_sdk28_sha256_digest=expected_sdk28_sha256_digest,
        stock_loader_artifact_sha256=stock_loader_artifact_sha256,
        stock_loader_artifact_range_start=loader_range_start,
        stock_loader_artifact_range_length=loader_range_length,
        boot_config_id=boot_config_id,
        allow_ordinary_userdata=bool(allow_flag),
    )


def compute_baseline_manifest_digest(manifest: BaselineCertificationManifest) -> bytes:
    """Real SHA-256 (hashlib, portable) over the canonical 89-byte
    encoding -- must reach a byte-identical result to the C++
    BaselineCertificationManifestCodec::computeDigestSha256 for the same
    field values; the device recomputes this from its own freshly
    measured evidence, never a cached/trusted value from the CLI."""
    return hashlib.sha256(serialize_baseline_manifest(manifest)).digest()


# uid(8) + fullPK(32) + form(1) + selector(2) + profile(4) + layout(4) +
# role(4) + consentOwner(32) + operation(1) + txnId(16) + revision(4) +
# predecessor(16) + manifestDigest(32) + txFloor(4) + rxFloor(4) +
# issuerKeyId(2) + issuedAt(8) = 174 bytes. Mirrors
# AuthorityCodec::kSignedMessageBytes exactly. (Astra29: the prior
# 206-byte layout also carried a 32-byte expected_root_digest_sha256
# field, now removed entirely.)
_SIGNED_MESSAGE_FORMAT = ">8s32sBHIII32sB16sI16s32sIIHQ"
SIGNED_MESSAGE_BYTES = struct.calcsize(_SIGNED_MESSAGE_FORMAT)
RECORD_BYTES = SIGNED_MESSAGE_BYTES + SIGNATURE_BYTES

assert SIGNED_MESSAGE_BYTES == 174, SIGNED_MESSAGE_BYTES
assert RECORD_BYTES == 238, RECORD_BYTES


def serialize_signed_message(txn: AuthorityTransaction) -> bytes:
    """Serializes only the fields the issuer signature covers -- exactly
    what gets passed to `openssl pkeyutl -sign -rawin`."""
    b = txn.binding
    return struct.pack(
        _SIGNED_MESSAGE_FORMAT,
        _require_len("hardware_uid", b.hardware_uid, HARDWARE_UID_BYTES),
        _require_len("mesh_full_public_key", b.mesh_full_public_key, PUBLIC_KEY_BYTES),
        int(b.crypto_form),
        b.group_selector,
        b.profile_id,
        b.layout_id,
        b.historical_initial_role_id,
        _require_len("consent_owner_public_key", b.consent_owner_public_key, PUBLIC_KEY_BYTES),
        int(txn.operation),
        _require_len("transaction_id", txn.transaction_id, TRANSACTION_ID_BYTES),
        txn.revision,
        _require_len("predecessor_transaction_id", txn.predecessor_transaction_id, TRANSACTION_ID_BYTES),
        _require_len("manifest_digest_sha256", txn.manifest_digest_sha256, DIGEST_BYTES),
        txn.initial_tx_sequence_floor,
        txn.initial_rx_replay_floor,
        txn.issuer_key_id,
        txn.issued_at_unix_seconds,
    )


def serialize_record(txn: AuthorityTransaction) -> bytes:
    """Serializes the full durable record: signed message + signature.
    The signature itself is deliberately excluded from what it covers --
    a signature cannot cover itself."""
    return serialize_signed_message(txn) + _require_len(
        "issuer_signature_ed25519", txn.issuer_signature_ed25519, SIGNATURE_BYTES
    )


def compute_record_digest_sha256(txn: AuthorityTransaction) -> bytes:
    """A = SHA256(the EXACT RECORD_BYTES durable record, INCLUDING the
    issuer signature) -- mirrors AuthorityCodec::computeRecordDigestSha256
    exactly. This is the digest every wrapper that binds "this exact
    signed grant" must use, never manifest_digest_sha256 (M, policy
    content only)."""
    return hashlib.sha256(serialize_record(txn)).digest()


# Canonical, domain-separated commitment formula for R, the "prepared
# store root" digest -- mirrors src/ota/authority/PreparedRootCommitment.h
# exactly. Defined here purely for offline tooling/tests that need to
# compute or verify R against real persisted bytes `p`; this module
# itself never fabricates real device/store content for `p`.
PREPARED_ROOT_COMMITMENT_DOMAIN = b"MeshCore/OTA/prepared-store-root/v1"
assert len(PREPARED_ROOT_COMMITMENT_DOMAIN) == 35


class PreparedRootCommitmentError(AuthorityCodecError):
    """Raised by compute_prepared_root_commitment_sha256 on a malformed
    (p, len(p)) pair -- mirrors PreparedRootCommitment::Result on the
    C++ side: the length is checked BEFORE p is ever hashed, so a caller
    cannot get a digest that silently pretends p was present when it
    wasn't, and an impossibly large length is refused without ever
    reading/allocating p_len bytes."""


def compute_prepared_root_commitment_sha256(p: bytes) -> bytes:
    if p is None:
        # Mirrors the C++ "p == nullptr with p_len > 0" refusal: Python
        # has no null-pointer-with-a-positive-length concept for a bytes
        # object (len(None) itself can't be computed), so the analogous
        # failure mode here is an explicit caller passing None instead of
        # real (possibly empty) bytes -- refused the same way, never
        # silently treated as b"".
        raise PreparedRootCommitmentError("p must be bytes (use b'' for empty P, never None)")
    if len(p) > 0xFFFFFFFF:
        # Checked before struct.pack/hashing -- refused on the length
        # value alone, the same bound C++ enforces before any read.
        raise PreparedRootCommitmentError(f"len(p)={len(p)} exceeds UINT32_MAX and would silently narrow in BE32")
    h = hashlib.sha256()
    h.update(PREPARED_ROOT_COMMITMENT_DOMAIN)
    h.update(struct.pack(">I", len(p)))
    h.update(p)
    return h.digest()


def parse_record(data: bytes) -> AuthorityTransaction:
    """Parses a full durable record. Fails closed with a specific typed
    exception on any malformed, truncated, or semantically invalid
    input -- never returns a partially-populated transaction.

    Astra29: this also intentionally covers legacy-format rejection -- a
    238-byte-vs-270-byte (pre-Astra29 expected_root_digest_sha256 layout)
    mismatch fails closed with the same explicit RecordTooLong/
    RecordTooShort exception as any other malformed input, never silently
    reinterpreted or truncated."""
    if len(data) < RECORD_BYTES:
        raise RecordTooShort(f"record is {len(data)} bytes, need {RECORD_BYTES}")
    if len(data) > RECORD_BYTES:
        raise RecordTooLong(f"record is {len(data)} bytes, expected exactly {RECORD_BYTES}")

    (
        hardware_uid,
        mesh_full_public_key,
        form_raw,
        selector,
        profile_id,
        layout_id,
        role_id,
        consent_owner_public_key,
        operation_raw,
        transaction_id,
        revision,
        predecessor_transaction_id,
        manifest_digest,
        tx_floor,
        rx_floor,
        issuer_key_id,
        issued_at,
    ) = struct.unpack(_SIGNED_MESSAGE_FORMAT, data[:SIGNED_MESSAGE_BYTES])
    signature = data[SIGNED_MESSAGE_BYTES:RECORD_BYTES]

    if form_raw not in (int(CryptoDomainForm.PAIRWISE), int(CryptoDomainForm.GROUP)):
        raise InvalidCryptoForm(f"unrecognized crypto domain form byte {form_raw:#x}")
    crypto_form = CryptoDomainForm(form_raw)
    if crypto_form == CryptoDomainForm.PAIRWISE and selector != 0:
        raise InvalidGroupSelectorForPairwise("groupSelector must be 0 for a Pairwise crypto domain")

    if operation_raw not in (
        int(AuthorityOperation.COMMISSION),
        int(AuthorityOperation.REPAIR),
        int(AuthorityOperation.REKEY),
        int(AuthorityOperation.CERTIFY_EXISTING_BASELINE),
    ):
        raise InvalidOperation(f"unrecognized authority operation byte {operation_raw:#x}")

    binding = AuthorityBinding(
        hardware_uid=hardware_uid,
        mesh_full_public_key=mesh_full_public_key,
        crypto_form=crypto_form,
        group_selector=selector,
        profile_id=profile_id,
        layout_id=layout_id,
        historical_initial_role_id=role_id,
        consent_owner_public_key=consent_owner_public_key,
    )
    return AuthorityTransaction(
        binding=binding,
        operation=AuthorityOperation(operation_raw),
        transaction_id=transaction_id,
        revision=revision,
        predecessor_transaction_id=predecessor_transaction_id,
        manifest_digest_sha256=manifest_digest,
        initial_tx_sequence_floor=tx_floor,
        initial_rx_replay_floor=rx_floor,
        issuer_key_id=issuer_key_id,
        issued_at_unix_seconds=issued_at,
        issuer_signature_ed25519=signature,
    )


# ---------------------------------------------------------------------
# Offline Ed25519 signing/verification via openssl subprocess -- no
# Python crypto library dependency, matching
# bootloader/xiao_nrf52840_ota/tools/sign_image.py and
# provision_lab_key.py's existing conventions exactly.
# ---------------------------------------------------------------------

_SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")


class SigningError(Exception):
    pass


def generate_issuer_keypair(key_dir: Path, name: str = "issuer") -> Tuple[Path, Path]:
    """Generates a brand-new Ed25519 issuer keypair under the explicitly
    given `key_dir` (never a default/home-directory path -- callers, both
    the CLI and tests, must always pass this in). Refuses to overwrite an
    existing private key."""
    key_dir.mkdir(parents=True, exist_ok=True)
    private_path = key_dir / f"{name}-ed25519-private.pem"
    public_path = key_dir / f"{name}-ed25519-public.pem"
    if private_path.exists():
        raise SigningError(f"refusing to overwrite existing issuer private key: {private_path}")
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_path)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)],
        check=True, capture_output=True,
    )
    return private_path, public_path


def read_raw_public_key(public_key_pem: Path) -> bytes:
    der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key_pem), "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    if der[:12] != _SPKI_ED25519_PREFIX or len(der) != 44:
        raise SigningError("unexpected Ed25519 SubjectPublicKeyInfo encoding")
    return der[-32:]


def sign_bytes(message: bytes, private_key_pem: Path, work_dir: Path) -> bytes:
    """Signs `message` with the issuer's Ed25519 private key. `work_dir`
    must be an explicit, already-existing scratch directory (repository
    .tmp in tests/CLI use) -- this function never touches /tmp."""
    work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work_dir) as scratch:
        scratch_path = Path(scratch)
        message_path = scratch_path / "message.bin"
        signature_path = scratch_path / "signature.bin"
        message_path.write_bytes(message)
        subprocess.run(
            [
                "openssl", "pkeyutl", "-sign", "-rawin",
                "-inkey", str(private_key_pem),
                "-in", str(message_path),
                "-out", str(signature_path),
            ],
            check=True, capture_output=True,
        )
        signature = signature_path.read_bytes()
    if len(signature) != SIGNATURE_BYTES:
        raise SigningError(f"unexpected Ed25519 signature size {len(signature)}")
    return signature


def verify_bytes(message: bytes, signature: bytes, public_key_raw32: bytes, work_dir: Path) -> bool:
    """Verifies `signature` over `message` against a raw 32-byte Ed25519
    public key, using openssl exclusively (no production fallback: any
    subprocess/tooling failure is a verification failure, never an
    exception swallowed into a silent `True`)."""
    if len(public_key_raw32) != PUBLIC_KEY_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work_dir) as scratch:
        scratch_path = Path(scratch)
        message_path = scratch_path / "message.bin"
        signature_path = scratch_path / "signature.bin"
        der_path = scratch_path / "public.der"
        message_path.write_bytes(message)
        signature_path.write_bytes(signature)
        der_path.write_bytes(_SPKI_ED25519_PREFIX + public_key_raw32)
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-rawin",
                "-pubin", "-inkey", str(der_path), "-keyform", "DER",
                "-in", str(message_path), "-sigfile", str(signature_path),
            ],
            capture_output=True,
        )
    return result.returncode == 0


# ---------------------------------------------------------------------
# Two-copy durable SQLite registry. Real storage semantics: append-only
# rows, an explicit committed transaction, and a FRESH readback (new
# connection, full re-scan) before a write is ever treated as durable.
# There is no in-process cache anywhere below -- every read reopens the
# database file from scratch, which is what makes "close this object,
# construct a brand-new one against the same path" (used throughout
# scripts/tests/test_ota_authority_registry.py) a genuine cold read.
# ---------------------------------------------------------------------


@dataclass
class StoredTransactionRecord:
    txn: AuthorityTransaction
    state: TransactionState
    prepared_root_digest_sha256: bytes = bytes(DIGEST_BYTES)
    # Astra29: ConsumedPrepared is explicitly "root UNBOUND" until the
    # device has actually staged/ACKed a real root -- mirrors
    # AuthorityRegistryPort.h's StoredTransactionRecord::rootBound
    # exactly. ActivationSpent MUST always have root_bound == True
    # (enforced by append_state_transition); a stored ActivationSpent
    # with root_bound == False is a contradiction, always Uncertain.
    root_bound: bool = False
    challenge: bytes = bytes(CHALLENGE_BYTES)

    def same_transaction_identity(self, other: "StoredTransactionRecord") -> bool:
        return self.txn.transaction_id == other.txn.transaction_id

    def same_signed_content(self, other: "StoredTransactionRecord") -> bool:
        return serialize_record(self.txn) == serialize_record(other.txn)


class ReconciliationOutcome(IntEnum):
    AGREED = 0
    RECOVERED_FROM_SINGLE_COPY = 1
    UNCERTAIN = 2
    NOT_FOUND = 3


@dataclass
class ReconciliationResult:
    outcome: ReconciliationOutcome
    resolved: Optional[StoredTransactionRecord] = None
    needs_replica_repair: bool = False


_TRANSITION_PAYLOAD_FORMAT = f">16sBB{DIGEST_BYTES}s{CHALLENGE_BYTES}s"


def _issued_payload(txn: AuthorityTransaction) -> bytes:
    return serialize_record(txn)


def _transition_payload(
    transaction_id: bytes, new_state: TransactionState, prepared_root: bytes, root_bound: bool, challenge: bytes
) -> bytes:
    return struct.pack(
        _TRANSITION_PAYLOAD_FORMAT,
        _require_len("transaction_id", transaction_id, TRANSACTION_ID_BYTES),
        int(new_state),
        1 if root_bound else 0,
        _require_len("prepared_root_digest_sha256", prepared_root, DIGEST_BYTES),
        _require_len("challenge", challenge, CHALLENGE_BYTES),
    )


_RECORD_KIND_ISSUED = 1
_RECORD_KIND_TRANSITION = 2


class _ScanStatus(IntEnum):
    """H4 fix: a registry-copy read can end in exactly one of three
    distinguishable ways. `MISSING` is the ONLY status that may ever be
    treated as a clean, empty, nothing-recorded registry -- reported
    strictly when the backing file is positively confirmed absent on
    disk (or exists but its schema was never created, which is
    equivalent since `_ensure_schema` always runs before any insert).
    Any OTHER open/read failure (lock timeout, permission denied, a
    corrupt file header) is `UNCERTAIN` and must be surfaced as such,
    never silently folded into "no history here": a transient failure
    that LOOKED like an empty registry would be indistinguishable from
    fabricated first-use proof."""

    OK = 0
    MISSING = 1
    UNCERTAIN = 2


def _fsync_parent_directory(path: Path) -> bool:
    """H5 fix, revised (mirrors FileAuthorityRegistryCopy.h's
    fsyncParentDirectory): fsync'ing a database file's own bytes is not
    durability-sufficient -- the PARENT DIRECTORY's own entry pointing at
    the file must also be fsync'd, or a crash immediately after creation
    can lose the directory entry entirely even though the file's own
    contents were fully synced.

    Previously called only once, gated on a freshly-checked
    `path.exists()` "did this call create the file" flag. That is unsafe
    against retry/reopen: a mere existence check proves nothing about
    whether any PRIOR parent-directory fsync actually succeeded -- if the
    first creating append's directory fsync failed (itself correctly
    reported as a failed append), the file still exists on disk
    afterwards, so any later retry call would see `existed_before ==
    True` and skip the directory fsync forever. An in-memory "already
    synced" flag has the same defect (does not survive process
    reopen/retry). The only safe invariant is: every successful append
    unconditionally fsyncs the parent directory before being allowed to
    report success -- a deliberately simple, conservative, always-pay
    host-side durability cost (no radio/CPU budget applies to host
    tooling)."""
    directory = str(path.parent) if str(path.parent) else "."
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return False
    try:
        os.fsync(fd)
    except OSError:
        os.close(fd)
        return False
    try:
        os.close(fd)
    except OSError:
        return False
    return True


class AuthorityRegistryCopy:
    """A single real SQLite-file-backed registry copy. The constructor
    performs zero I/O (matching the C++ FileAuthorityRegistryCopy
    contract) -- the schema is created lazily on first append."""

    def __init__(self, db_path: Path):
        self._path = Path(db_path)
        # FOR TESTS ONLY: real production construction never sets this.
        # Lets a test genuinely fault a specific parent-directory fsync
        # call to prove the H5 retry/reopen durability fix behaviorally
        # -- never used to merely introspect whether fsync was called.
        self.fsync_parent_directory_override_for_tests: Optional[Callable[[Path], bool]] = None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _read_rows(self, columns: str) -> Tuple[List[Tuple], "_ScanStatus"]:
        """Shared real read path for read_latest/_scan_all_records (H4
        fix): a read must NEVER implicitly create the backing file as a
        side effect (opens in an explicit read-only URI mode, which
        fails rather than silently creating a fresh empty database), and
        never conflates a positively confirmed absent file/schema with
        any other open/read failure."""
        if not self._path.exists():
            return [], _ScanStatus.MISSING
        uri = f"file:{self._path}?mode=ro"
        try:
            conn = sqlite3.connect(uri, uri=True, timeout=5.0)
            try:
                rows = list(conn.execute(f"SELECT {columns} FROM authority_log ORDER BY id"))
            finally:
                conn.close()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc):
                # The file itself exists (confirmed above) but its schema
                # was never created -- genuinely nothing was ever
                # committed here, since _ensure_schema always runs before
                # any insert.
                return [], _ScanStatus.MISSING
            # Lock timeout, permission denied, "unable to open database
            # file" (e.g. a deleted-between-exists()-and-connect() race),
            # or any other operational failure: never clean absence.
            return [], _ScanStatus.UNCERTAIN
        except sqlite3.DatabaseError:
            return [], _ScanStatus.UNCERTAIN  # Corrupt file header, etc.
        return rows, _ScanStatus.OK

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS authority_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind INTEGER NOT NULL,
                transaction_id TEXT NOT NULL,
                payload BLOB NOT NULL
            )"""
        )

    def append_issued(self, txn: AuthorityTransaction) -> bool:
        existing, corrupt = self.read_latest(txn.transaction_id_hex())
        if corrupt or existing is not None:
            return False  # Already present: never overwritten.
        return self._append(_RECORD_KIND_ISSUED, txn.transaction_id_hex(), _issued_payload(txn))

    def append_state_transition(
        self,
        transaction_id: bytes,
        new_state: TransactionState,
        prepared_root_digest_sha256: bytes,
        root_bound: bool,
        challenge: bytes,
    ) -> bool:
        transaction_id_hex = transaction_id.hex()
        existing, corrupt = self.read_latest(transaction_id_hex)
        if corrupt or existing is None:
            return False
        if _STATE_RANK[new_state] != _STATE_RANK[existing.state] + 1:
            return False  # Only a strict single-step advance is ever accepted.
        # ActivationSpent must always be rootBound -- never durably
        # persist a self-contradictory "spent but no root known" record.
        if new_state == TransactionState.ACTIVATION_SPENT and not root_bound:
            return False
        if new_state == TransactionState.ACTIVATION_SPENT and existing.root_bound:
            # Must activate the EXISTING matching prepared root, never a
            # different one -- but only enforced once the prior record
            # actually bound a root already (a fresh ConsumedPrepared->
            # ActivationSpent advance is the FIRST time a root becomes
            # known, so there is nothing yet to conflict with).
            if existing.prepared_root_digest_sha256 != prepared_root_digest_sha256:
                return False
        payload = _transition_payload(transaction_id, new_state, prepared_root_digest_sha256, root_bound, challenge)
        return self._append(_RECORD_KIND_TRANSITION, transaction_id_hex, payload)

    def _append(self, kind: int, transaction_id_hex: str, payload: bytes) -> bool:
        try:
            conn = self._connect()
            try:
                self._ensure_schema(conn)
                cur = conn.execute(
                    "INSERT INTO authority_log(kind, transaction_id, payload) VALUES (?, ?, ?)",
                    (kind, transaction_id_hex, payload),
                )
                row_id = cur.lastrowid
            finally:
                conn.close()
        except sqlite3.DatabaseError:
            return False

        # Durable checked commit: reopen a FRESH connection and read the
        # row back before this append is ever reported as successful.
        try:
            verify_conn = sqlite3.connect(str(self._path), timeout=5.0)
            try:
                row = verify_conn.execute(
                    "SELECT kind, transaction_id, payload FROM authority_log WHERE id = ?", (row_id,)
                ).fetchone()
            finally:
                verify_conn.close()
        except sqlite3.DatabaseError:
            return False
        if not (row is not None and row[0] == kind and row[1] == transaction_id_hex and row[2] == payload):
            return False

        # H5 fix, revised: unconditionally fsync the parent directory
        # before this append may be reported as durable, regardless of
        # whether the file "already existed" by the time we got here --
        # see _fsync_parent_directory's docstring for why existence alone
        # proves nothing about prior directory-entry durability.
        sync_fn = self.fsync_parent_directory_override_for_tests or _fsync_parent_directory
        if not sync_fn(self._path):
            return False
        return True

    def read_latest(self, transaction_id_hex: str) -> Tuple[Optional[StoredTransactionRecord], bool]:
        """Returns (record_or_None, corrupt_but_present). Every call opens
        a brand-new read-only connection and re-scans from row 1 -- no
        cache, and never implicitly creates the backing file."""
        rows, status = self._read_rows("id, kind, transaction_id, payload")
        if status == _ScanStatus.MISSING:
            return None, False  # Positively confirmed absent: a clean "nothing recorded".
        if status == _ScanStatus.UNCERTAIN:
            return None, True  # Open/read failure: never clean absence.

        found: Optional[StoredTransactionRecord] = None
        any_invalid = False
        for _row_id, kind, transaction_id_hex_row, payload in rows:
            if kind == _RECORD_KIND_ISSUED:
                try:
                    txn = parse_record(payload)
                except AuthorityCodecError:
                    any_invalid = True
                    continue
                if txn.transaction_id_hex() == transaction_id_hex:
                    found = StoredTransactionRecord(txn=txn, state=TransactionState.ISSUED)
            elif kind == _RECORD_KIND_TRANSITION:
                if transaction_id_hex_row != transaction_id_hex:
                    continue
                try:
                    txn_id, state_raw, root_bound_raw, prepared_root, challenge = struct.unpack(
                        _TRANSITION_PAYLOAD_FORMAT, payload
                    )
                except struct.error:
                    any_invalid = True
                    continue
                if state_raw not in (
                    int(TransactionState.CONSUMED_PREPARED),
                    int(TransactionState.ACTIVATION_SPENT),
                ):
                    any_invalid = True
                    continue
                if root_bound_raw not in (0, 1):
                    any_invalid = True
                    continue
                if found is None:
                    # A transition with no preceding Issued record for
                    # this id is unexplained history -- surface it as
                    # corruption, never as a usable state.
                    any_invalid = True
                    continue
                found.state = TransactionState(state_raw)
                found.root_bound = root_bound_raw != 0
                found.prepared_root_digest_sha256 = prepared_root
                found.challenge = challenge
            else:
                any_invalid = True

        # A later corrupt/unreadable slot must never be masked behind an
        # earlier still-parseable state -- always propagate any_invalid,
        # even when `found` reflects a genuine (but possibly stale) record.
        return found, any_invalid

    def _scan_all_records(self) -> Tuple[dict, bool]:
        """Shared full-file scan used by both read_latest_activation_for_owner
        and read_latest_physical_lineage -- mirrors
        FileAuthorityRegistryCopy::scanAllRecords exactly (builds the
        full in-memory Issued+transition map once, propagating any
        corruption seen along the way). H4 fix: uses the same read-only,
        never-implicitly-creating `_read_rows` path as read_latest, and
        an open/read failure (`UNCERTAIN`) is never folded into a clean
        empty result."""
        rows, status = self._read_rows("kind, transaction_id, payload")
        if status == _ScanStatus.MISSING:
            return {}, False
        if status == _ScanStatus.UNCERTAIN:
            return {}, True

        any_invalid = False
        all_records: dict = {}
        for kind, transaction_id_hex_row, payload in rows:
            if kind == _RECORD_KIND_ISSUED:
                try:
                    txn = parse_record(payload)
                except AuthorityCodecError:
                    any_invalid = True
                    continue
                all_records[txn.transaction_id_hex()] = StoredTransactionRecord(
                    txn=txn, state=TransactionState.ISSUED
                )
            elif kind == _RECORD_KIND_TRANSITION:
                rec = all_records.get(transaction_id_hex_row)
                if rec is None:
                    # Unexplained history: a transition with no preceding
                    # Issued record for this id is corruption, never a
                    # silently-skipped no-op.
                    any_invalid = True
                    continue
                try:
                    _txn_id, state_raw, root_bound_raw, prepared_root, challenge = struct.unpack(
                        _TRANSITION_PAYLOAD_FORMAT, payload
                    )
                except struct.error:
                    any_invalid = True
                    continue
                if state_raw not in (
                    int(TransactionState.CONSUMED_PREPARED),
                    int(TransactionState.ACTIVATION_SPENT),
                ):
                    any_invalid = True
                    continue
                if root_bound_raw not in (0, 1):
                    any_invalid = True
                    continue
                rec.state = TransactionState(state_raw)
                rec.root_bound = root_bound_raw != 0
                rec.prepared_root_digest_sha256 = prepared_root
                rec.challenge = challenge
            else:
                any_invalid = True
        return all_records, any_invalid

    def read_latest_activation_for_owner(
        self, owner: AuthorityBinding
    ) -> Tuple[Optional[StoredTransactionRecord], bool]:
        """Returns (record_or_None, corrupt_but_present) -- mirrors
        read_latest's corruption-propagation discipline (HIGH4): an
        unparseable Issued record, a malformed transition, or a
        transition with no matching Issued record must never be
        silently skipped, they must surface as untrusted history."""
        all_records, any_invalid = self._scan_all_records()

        best = None
        for rec in all_records.values():
            if rec.state != TransactionState.ACTIVATION_SPENT:
                continue
            # H1 fix: CertifyExistingBaseline is a narrower, non-lineage
            # grant that deliberately never enters the Commission/Repair/
            # Rekey Issued->ConsumedPrepared->ActivationSpent lifecycle --
            # excluded explicitly here so a signed baseline certificate
            # can never be mistaken for "this owner already has
            # ActivationSpent history", which would wrongly block a
            # genuine first Commission.
            if rec.txn.operation == AuthorityOperation.CERTIFY_EXISTING_BASELINE:
                continue
            if not rec.txn.binding.same_ownership(owner):
                continue
            if best is None or rec.txn.revision > best.txn.revision:
                best = rec
        return best, any_invalid

    def read_latest_physical_lineage(
        self, physical_device: AuthorityBinding
    ) -> Tuple[Optional[StoredTransactionRecord], bool]:
        """H-finding fix: latest-revision record for this PHYSICAL device
        (any fullPK, any state), used by the REKEY/COMMISSION CLI paths'
        fork-prevention fence -- mirrors
        FileAuthorityRegistryCopy::readLatestPhysicalLineage exactly.
        Sol43 HIGH fix: this now filters by same_physical_lifetime
        (hardware_uid ONLY) rather than same_device_identity
        (hardware_uid+crypto_form+group_selector+layout_id), since
        keeping crypto-domain/layout in this key let a second signed
        transaction for the SAME physical chip under a different
        crypto-domain/layout escape this fence entirely. A pending
        (Issued/ConsumedPrepared, not yet ActivationSpent) successor
        under a DIFFERENT fullPK still counts here, unlike
        read_latest_activation_for_owner above which only ever sees
        ActivationSpent. If more than one DISTINCT transaction id is
        found at the same highest revision for this physical device,
        that is an unresolved fork within this single copy -- surfaced
        as corrupt, never silently resolved by picking one."""
        all_records, any_invalid = self._scan_all_records()

        best: Optional[StoredTransactionRecord] = None
        fork_at_highest_revision = False
        for rec in all_records.values():
            # H1 fix: same CertifyExistingBaseline exclusion as
            # read_latest_activation_for_owner above -- this scan exists
            # purely to fence Commission/Repair/Rekey forks, never to
            # treat a baseline certificate as bootstrap/lineage history
            # for this physical device.
            if rec.txn.operation == AuthorityOperation.CERTIFY_EXISTING_BASELINE:
                continue
            if not rec.txn.binding.same_physical_lifetime(physical_device):
                continue
            if best is None or rec.txn.revision > best.txn.revision:
                best = rec
                fork_at_highest_revision = False
            elif rec.txn.revision == best.txn.revision and rec.txn.transaction_id != best.txn.transaction_id:
                # Two genuinely different transactions claim the same
                # revision for the same physical device -- a fork. Never
                # silently keep whichever happened to be scanned first.
                fork_at_highest_revision = True
        if fork_at_highest_revision:
            any_invalid = True
            best = None
        return best, any_invalid

    def read_latest_ownership_lineage(
        self, owner: AuthorityBinding
    ) -> Tuple[Optional[StoredTransactionRecord], bool]:
        """H3 fix: mirrors read_latest_physical_lineage exactly, but
        filters by same_ownership (UID+fullPK+cryptoDomain+layout)
        instead of same_device_identity (UID+cryptoDomain+layout only),
        across ANY state. Used by the COMMISSION CLI path's genesis
        fork-prevention fence: read_latest_activation_for_owner above is
        structurally blind to a sibling revision-0 Commission for this
        SAME owner that has reached Issued or ConsumedPrepared but not
        yet ActivationSpent."""
        all_records, any_invalid = self._scan_all_records()

        best: Optional[StoredTransactionRecord] = None
        fork_at_highest_revision = False
        for rec in all_records.values():
            # H1 fix: same CertifyExistingBaseline exclusion -- a signed
            # baseline certificate (Issued forever, never advances) must
            # never be mistaken for an existing Commission genesis when
            # fencing a brand-new first Commission for this exact
            # ownership.
            if rec.txn.operation == AuthorityOperation.CERTIFY_EXISTING_BASELINE:
                continue
            if not rec.txn.binding.same_ownership(owner):
                continue
            if best is None or rec.txn.revision > best.txn.revision:
                best = rec
                fork_at_highest_revision = False
            elif rec.txn.revision == best.txn.revision and rec.txn.transaction_id != best.txn.transaction_id:
                fork_at_highest_revision = True
        if fork_at_highest_revision:
            any_invalid = True
            best = None
        return best, any_invalid

    @property
    def path(self) -> Path:
        return self._path


def reconcile_copies(
    a_found: Optional[StoredTransactionRecord],
    a_corrupt: bool,
    b_found: Optional[StoredTransactionRecord],
    b_corrupt: bool,
) -> ReconciliationResult:
    """Pure dominance function, mirroring
    src/ota/authority/AuthorityRegistryPort.h::reconcileCopies exactly."""
    a_valid = a_found is not None and not a_corrupt
    b_valid = b_found is not None and not b_corrupt

    if not a_valid and not b_valid:
        if a_corrupt or b_corrupt:
            return ReconciliationResult(ReconciliationOutcome.UNCERTAIN)
        return ReconciliationResult(ReconciliationOutcome.NOT_FOUND)

    if a_valid and not b_valid:
        return ReconciliationResult(ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY, a_found, True)
    if b_valid and not a_valid:
        return ReconciliationResult(ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY, b_found, True)

    assert a_found is not None and b_found is not None
    if not a_found.same_transaction_identity(b_found) or not a_found.same_signed_content(b_found):
        return ReconciliationResult(ReconciliationOutcome.UNCERTAIN)

    # ActivationSpent MUST always be rootBound by construction. A stored
    # ActivationSpent claiming root_bound == False is a contradiction --
    # never trusted as permission.
    if (a_found.state == TransactionState.ACTIVATION_SPENT and not a_found.root_bound) or (
        b_found.state == TransactionState.ACTIVATION_SPENT and not b_found.root_bound
    ):
        return ReconciliationResult(ReconciliationOutcome.UNCERTAIN)

    if a_found.state == b_found.state:
        if a_found.state != TransactionState.ISSUED:
            if a_found.root_bound != b_found.root_bound:
                return ReconciliationResult(ReconciliationOutcome.UNCERTAIN)
            if a_found.root_bound and (
                a_found.prepared_root_digest_sha256 != b_found.prepared_root_digest_sha256
            ):
                return ReconciliationResult(ReconciliationOutcome.UNCERTAIN)
        return ReconciliationResult(ReconciliationOutcome.AGREED, a_found, False)

    higher, lower = (
        (a_found, b_found) if _STATE_RANK[a_found.state] > _STATE_RANK[b_found.state] else (b_found, a_found)
    )
    if lower.state != TransactionState.ISSUED and lower.root_bound and (
        lower.prepared_root_digest_sha256 != higher.prepared_root_digest_sha256
    ):
        return ReconciliationResult(ReconciliationOutcome.UNCERTAIN)
    return ReconciliationResult(ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY, higher, True)


class AuthorityRegistryPair:
    def __init__(self, copy_a: AuthorityRegistryCopy, copy_b: AuthorityRegistryCopy):
        self.copy_a = copy_a
        self.copy_b = copy_b

    def commit_issued(self, txn: AuthorityTransaction) -> bool:
        a_ok = self.copy_a.append_issued(txn)
        b_ok = self.copy_b.append_issued(txn)
        return a_ok and b_ok

    def commit_state_transition(
        self,
        transaction_id: bytes,
        new_state: TransactionState,
        prepared_root_digest_sha256: bytes,
        root_bound: bool,
        challenge: bytes,
    ) -> bool:
        # Defense in depth: ActivationSpent must always be rootBound, even
        # if a caller mistakenly passes False -- refuse outright rather
        # than durably persist a self-contradictory record to either copy.
        if new_state == TransactionState.ACTIVATION_SPENT and not root_bound:
            return False
        a_ok = self.copy_a.append_state_transition(
            transaction_id, new_state, prepared_root_digest_sha256, root_bound, challenge
        )
        b_ok = self.copy_b.append_state_transition(
            transaction_id, new_state, prepared_root_digest_sha256, root_bound, challenge
        )
        return a_ok and b_ok

    def reconcile(self, transaction_id: bytes) -> ReconciliationResult:
        transaction_id_hex = transaction_id.hex()
        a_found, a_corrupt = self.copy_a.read_latest(transaction_id_hex)
        b_found, b_corrupt = self.copy_b.read_latest(transaction_id_hex)
        return reconcile_copies(a_found, a_corrupt, b_found, b_corrupt)

    def reconcile_latest_activation_for_owner(self, owner: "AuthorityBinding") -> ReconciliationResult:
        """Mirrors AuthorityRegistryPair::reconcileLatestActivationForOwner
        in AuthorityRegistryPort.h: dominance reconciliation restricted to
        the newest ActivationSpent record for this exact ownership
        identity (HIGH6's prerequisite for rejecting relabeled/duplicate
        Commission and unchained Repair/Rekey)."""
        a_found, a_corrupt = self.copy_a.read_latest_activation_for_owner(owner)
        b_found, b_corrupt = self.copy_b.read_latest_activation_for_owner(owner)
        return reconcile_copies(a_found, a_corrupt, b_found, b_corrupt)

    def reconcile_physical_lineage(self, physical_device: "AuthorityBinding") -> ReconciliationResult:
        """Fork-prevention fence for the REKEY CLI path: combines both
        copies' read_latest_physical_lineage scans with REVISION
        dominance (not state-rank -- a pending successor under a
        DIFFERENT fullPK still counts, at ANY state), mirroring
        AuthorityRegistryPair::reconcilePhysicalLineage exactly.
        Equal-revision disagreement (including a genuine fork -- two
        DIFFERENT transaction ids at the same revision, whether within
        one copy or across the two copies here) is always UNCERTAIN,
        never silently resolved toward one candidate."""
        a_found, a_corrupt = self.copy_a.read_latest_physical_lineage(physical_device)
        b_found, b_corrupt = self.copy_b.read_latest_physical_lineage(physical_device)

        a_valid = a_found is not None and not a_corrupt
        b_valid = b_found is not None and not b_corrupt

        if not a_valid and not b_valid:
            outcome = ReconciliationOutcome.UNCERTAIN if (a_corrupt or b_corrupt) else ReconciliationOutcome.NOT_FOUND
            return ReconciliationResult(outcome)
        if a_valid and not b_valid:
            return ReconciliationResult(ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY, a_found, True)
        if b_valid and not a_valid:
            return ReconciliationResult(ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY, b_found, True)

        assert a_found is not None and b_found is not None
        if a_found.txn.revision == b_found.txn.revision:
            if not a_found.same_transaction_identity(b_found) or not a_found.same_signed_content(b_found):
                return ReconciliationResult(ReconciliationOutcome.UNCERTAIN)
            return ReconciliationResult(ReconciliationOutcome.AGREED, a_found, False)

        higher, lower = (a_found, b_found) if a_found.txn.revision > b_found.txn.revision else (b_found, a_found)
        return ReconciliationResult(ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY, higher, True)

    def reconcile_ownership_lineage(self, owner: "AuthorityBinding") -> ReconciliationResult:
        """H3 fork-prevention fence for the COMMISSION CLI path: combines
        both copies' read_latest_ownership_lineage scans with the SAME
        dominance treatment as reconcile_physical_lineage above, but
        keyed on the EXACT owner rather than physical device identity,
        across ANY state. This is what lets a SECOND revision-0
        Commission for an owner that already has an Issued-but-not-yet-
        spent record be rejected, not just one that is already
        ActivationSpent."""
        a_found, a_corrupt = self.copy_a.read_latest_ownership_lineage(owner)
        b_found, b_corrupt = self.copy_b.read_latest_ownership_lineage(owner)

        a_valid = a_found is not None and not a_corrupt
        b_valid = b_found is not None and not b_corrupt

        if not a_valid and not b_valid:
            outcome = ReconciliationOutcome.UNCERTAIN if (a_corrupt or b_corrupt) else ReconciliationOutcome.NOT_FOUND
            return ReconciliationResult(outcome)
        if a_valid and not b_valid:
            return ReconciliationResult(ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY, a_found, True)
        if b_valid and not a_valid:
            return ReconciliationResult(ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY, b_found, True)

        assert a_found is not None and b_found is not None
        if a_found.txn.revision == b_found.txn.revision:
            if not a_found.same_transaction_identity(b_found) or not a_found.same_signed_content(b_found):
                return ReconciliationResult(ReconciliationOutcome.UNCERTAIN)
            return ReconciliationResult(ReconciliationOutcome.AGREED, a_found, False)

        higher, lower = (a_found, b_found) if a_found.txn.revision > b_found.txn.revision else (b_found, a_found)
        return ReconciliationResult(ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY, higher, True)

    def confirm_both_copies_durable(
        self, transaction_id: bytes, minimum_state: TransactionState
    ) -> ReconciliationResult:
        """Fresh, COLD re-readback -- always re-opens/re-scans both
        copies from disk via reconcile() (NEVER trusts the in-memory
        boolean a prior commit_* call just returned) confirming BOTH
        copies durably AGREE on transaction_id at >= minimum_state
        before any permission may be released. Required immediately
        before EVERY authority permission release in the handshake
        driver below (ConsumedPrepared commit, and again immediately
        before ActivationSpent), not merely once at entry -- mirrors
        the C++ AuthorityCoordinator's own repeated durability
        reconfirmation discipline. Anything other than a clean AGREED
        result at >= minimum_state is treated identically to a failed
        commit by every caller."""
        result = self.reconcile(transaction_id)
        if result.outcome != ReconciliationOutcome.AGREED:
            return result
        if result.resolved is None or _STATE_RANK[result.resolved.state] < _STATE_RANK[minimum_state]:
            return ReconciliationResult(ReconciliationOutcome.UNCERTAIN)
        return result


# ---------------------------------------------------------------------
# PrepareAuthorizationV1 / ActivationAuthorizationV1 -- Python mirrors of
# src/ota/authority/PrepareAuthorizationCodec.h /
# ActivationAuthorizationCodec.h, byte-for-byte identical wire layout.
# These are the REAL, device-minted-challenge-bound, domain-separated
# signed objects the production host session below exchanges with a
# device over the Maintenance USB ABI (ObjectKind.PREPARE_AUTHORIZATION /
# ACTIVATION_AUTHORIZATION, both 267 bytes) -- NOT the simpler
# PreparePermit/ActivationPermit shapes AuthorityCoordinator's own C++
# unit tests still use internally (wiring the C++ coordinator itself to
# these is a separate, not-yet-done refactor tracked elsewhere, NOT
# claimed complete here). A host-chosen challenge alone never proves a
# fresh device-minted nonce was involved (Astra section D); binding to
# `device_fresh_challenge` sourced from the device's OWN measurement/ack
# entropy is what actually closes that gap.
# ---------------------------------------------------------------------

PREPARE_AUTH_SIGNED_DOMAIN = b"MeshCore/OTA/prepare-store-root/v1"
assert len(PREPARE_AUTH_SIGNED_DOMAIN) == 34, len(PREPARE_AUTH_SIGNED_DOMAIN)
ACTIVATION_AUTH_SIGNED_DOMAIN = b"MeshCore/OTA/activate-existing-root/v1"
assert len(ACTIVATION_AUTH_SIGNED_DOMAIN) == 38, len(ACTIVATION_AUTH_SIGNED_DOMAIN)

_BINDING_FORMAT = ">8s32sBHIII32s"
BINDING_BYTES = struct.calcsize(_BINDING_FORMAT)
assert BINDING_BYTES == 87, BINDING_BYTES


def serialize_binding(b: AuthorityBinding) -> bytes:
    """Mirrors AuthorityCodec::writeBindingFields exactly -- the same 87
    canonical bytes embedded as a prefix of serialize_signed_message,
    exposed standalone so PrepareAuthorizationV1/ActivationAuthorizationV1
    (which each embed a FULL AuthorityBinding, not a whole transaction)
    never need a throwaway AuthorityTransaction just to serialize one."""
    return struct.pack(
        _BINDING_FORMAT,
        _require_len("hardware_uid", b.hardware_uid, HARDWARE_UID_BYTES),
        _require_len("mesh_full_public_key", b.mesh_full_public_key, PUBLIC_KEY_BYTES),
        int(b.crypto_form),
        b.group_selector,
        b.profile_id,
        b.layout_id,
        b.historical_initial_role_id,
        _require_len("consent_owner_public_key", b.consent_owner_public_key, PUBLIC_KEY_BYTES),
    )


def parse_binding(data: bytes) -> AuthorityBinding:
    if len(data) < BINDING_BYTES:
        raise RecordTooShort(f"binding is {len(data)} bytes, need {BINDING_BYTES}")
    if len(data) > BINDING_BYTES:
        raise RecordTooLong(f"binding is {len(data)} bytes, expected exactly {BINDING_BYTES}")
    (hardware_uid, mesh_full_public_key, form_raw, selector, profile_id, layout_id, role_id,
     consent_owner_public_key) = struct.unpack(_BINDING_FORMAT, data)
    if form_raw not in (int(CryptoDomainForm.PAIRWISE), int(CryptoDomainForm.GROUP)):
        raise InvalidCryptoForm(f"unrecognized crypto domain form byte {form_raw:#x}")
    crypto_form = CryptoDomainForm(form_raw)
    if crypto_form == CryptoDomainForm.PAIRWISE and selector != 0:
        raise InvalidGroupSelectorForPairwise("groupSelector must be 0 for a Pairwise crypto domain")
    return AuthorityBinding(
        hardware_uid=hardware_uid, mesh_full_public_key=mesh_full_public_key, crypto_form=crypto_form,
        group_selector=selector, profile_id=profile_id, layout_id=layout_id,
        historical_initial_role_id=role_id, consent_owner_public_key=consent_owner_public_key,
    )


class PrepareRxContextKind(IntEnum):
    NONE = 0
    PEER = 1


_AUTH_BODY_PREFIX_FORMAT = f">{TRANSACTION_ID_BYTES}s{DIGEST_BYTES}s{DIGEST_BYTES}sI"
_AUTH_BODY_PREFIX_BYTES = struct.calcsize(_AUTH_BODY_PREFIX_FORMAT)
_AUTH_BODY_SUFFIX_FORMAT = f">{CHALLENGE_BYTES}s{CHALLENGE_BYTES}s"
_AUTH_BODY_SUFFIX_BYTES = struct.calcsize(_AUTH_BODY_SUFFIX_FORMAT)

AUTH_BODY_BYTES = _AUTH_BODY_PREFIX_BYTES + BINDING_BYTES + _AUTH_BODY_SUFFIX_BYTES
assert AUTH_BODY_BYTES == 203, AUTH_BODY_BYTES
AUTH_RECORD_BYTES = AUTH_BODY_BYTES + SIGNATURE_BYTES
assert AUTH_RECORD_BYTES == 267, AUTH_RECORD_BYTES


@dataclass
class PrepareAuthorizationV1:
    transaction_id: bytes
    grant_digest_sha256: bytes
    input_digest_sha256: bytes
    authorized_revision: int
    expected_binding: AuthorityBinding
    device_fresh_challenge: bytes
    host_nonce: bytes
    issuer_signature_ed25519: bytes = bytes(SIGNATURE_BYTES)


def serialize_prepare_authorization_body(p: PrepareAuthorizationV1) -> bytes:
    return (
        struct.pack(_AUTH_BODY_PREFIX_FORMAT,
                    _require_len("transaction_id", p.transaction_id, TRANSACTION_ID_BYTES),
                    _require_len("grant_digest_sha256", p.grant_digest_sha256, DIGEST_BYTES),
                    _require_len("input_digest_sha256", p.input_digest_sha256, DIGEST_BYTES),
                    p.authorized_revision)
        + serialize_binding(p.expected_binding)
        + struct.pack(_AUTH_BODY_SUFFIX_FORMAT,
                      _require_len("device_fresh_challenge", p.device_fresh_challenge, CHALLENGE_BYTES),
                      _require_len("host_nonce", p.host_nonce, CHALLENGE_BYTES))
    )


def serialize_prepare_authorization_record(p: PrepareAuthorizationV1) -> bytes:
    body = serialize_prepare_authorization_body(p)
    assert len(body) == AUTH_BODY_BYTES
    return body + _require_len("issuer_signature_ed25519", p.issuer_signature_ed25519, SIGNATURE_BYTES)


def serialize_prepare_authorization_signed_message(p: PrepareAuthorizationV1) -> bytes:
    return PREPARE_AUTH_SIGNED_DOMAIN + serialize_prepare_authorization_body(p)


def parse_prepare_authorization_record(data: bytes) -> PrepareAuthorizationV1:
    if len(data) < AUTH_RECORD_BYTES:
        raise RecordTooShort(f"prepare authorization record is {len(data)} bytes, need {AUTH_RECORD_BYTES}")
    if len(data) > AUTH_RECORD_BYTES:
        raise RecordTooLong(f"prepare authorization record is {len(data)} bytes, expected exactly {AUTH_RECORD_BYTES}")
    (transaction_id, grant_digest, input_digest, revision) = struct.unpack(
        _AUTH_BODY_PREFIX_FORMAT, data[:_AUTH_BODY_PREFIX_BYTES]
    )
    offset = _AUTH_BODY_PREFIX_BYTES
    binding = parse_binding(data[offset:offset + BINDING_BYTES])
    offset += BINDING_BYTES
    (device_fresh_challenge, host_nonce) = struct.unpack(
        _AUTH_BODY_SUFFIX_FORMAT, data[offset:offset + _AUTH_BODY_SUFFIX_BYTES]
    )
    offset += _AUTH_BODY_SUFFIX_BYTES
    signature = data[offset:offset + SIGNATURE_BYTES]
    offset += SIGNATURE_BYTES
    assert offset == AUTH_RECORD_BYTES
    return PrepareAuthorizationV1(
        transaction_id=transaction_id, grant_digest_sha256=grant_digest, input_digest_sha256=input_digest,
        authorized_revision=revision, expected_binding=binding, device_fresh_challenge=device_fresh_challenge,
        host_nonce=host_nonce, issuer_signature_ed25519=signature,
    )


# Exactly G(238) + C(238) + B(117) + rxContextKind(1) + peerFullPublicKey(32)
# = 626 input bytes -- mirrors PrepareAuthorizationCodec::kInputDigestSourceBytes
# exactly; never includes this wrapper's own body or any transport/signature bytes.
PREPARE_AUTH_INPUT_DIGEST_SOURCE_BYTES = RECORD_BYTES + RECORD_BYTES + BASELINE_MANIFEST_BYTES + 1 + PUBLIC_KEY_BYTES
assert PREPARE_AUTH_INPUT_DIGEST_SOURCE_BYTES == 626, PREPARE_AUTH_INPUT_DIGEST_SOURCE_BYTES


def build_prepare_authorization_input_bytes(
    grant: AuthorityTransaction,
    certify: AuthorityTransaction,
    manifest: BaselineCertificationManifest,
    rx_kind: "PrepareRxContextKind",
    peer_full_public_key: bytes,
) -> bytes:
    """The raw 626-byte PREPARE_INPUT material itself (G238 || C238 ||
    B117 || rxContextKind(1) || peerFullPublicKey(32)) -- per MAIN's
    adapter clarification this exact buffer must ALSO be uploaded to the
    device as ObjectKind.PREPARE_INPUT (not merely its digest folded into
    PrepareAuthorizationV1), so the device verifies the digest against
    retained material it holds itself rather than trusting an opaque
    digest alone."""
    buf = (
        serialize_record(grant)
        + serialize_record(certify)
        + serialize_baseline_manifest(manifest)
        + bytes((int(rx_kind),))
        + _require_len("peer_full_public_key", peer_full_public_key, PUBLIC_KEY_BYTES)
    )
    assert len(buf) == PREPARE_AUTH_INPUT_DIGEST_SOURCE_BYTES
    return buf


def compute_prepare_authorization_input_digest_sha256(
    grant: AuthorityTransaction,
    certify: AuthorityTransaction,
    manifest: BaselineCertificationManifest,
    rx_kind: "PrepareRxContextKind",
    peer_full_public_key: bytes,
) -> bytes:
    """Mirrors PrepareAuthorizationCodec::computeInputDigestSha256 exactly:
    SHA256(G238 || C238 || B117 || rxContextKind(1) || peerFullPublicKey(32))."""
    return hashlib.sha256(
        build_prepare_authorization_input_bytes(grant, certify, manifest, rx_kind, peer_full_public_key)
    ).digest()


@dataclass
class ActivationAuthorizationV1:
    transaction_id: bytes
    grant_digest_sha256: bytes
    prepared_root_digest_sha256: bytes
    spent_authorized_revision: int
    expected_binding: AuthorityBinding
    device_fresh_challenge: bytes
    host_nonce: bytes
    issuer_signature_ed25519: bytes = bytes(SIGNATURE_BYTES)


def serialize_activation_authorization_body(a: ActivationAuthorizationV1) -> bytes:
    return (
        struct.pack(_AUTH_BODY_PREFIX_FORMAT,
                    _require_len("transaction_id", a.transaction_id, TRANSACTION_ID_BYTES),
                    _require_len("grant_digest_sha256", a.grant_digest_sha256, DIGEST_BYTES),
                    _require_len("prepared_root_digest_sha256", a.prepared_root_digest_sha256, DIGEST_BYTES),
                    a.spent_authorized_revision)
        + serialize_binding(a.expected_binding)
        + struct.pack(_AUTH_BODY_SUFFIX_FORMAT,
                      _require_len("device_fresh_challenge", a.device_fresh_challenge, CHALLENGE_BYTES),
                      _require_len("host_nonce", a.host_nonce, CHALLENGE_BYTES))
    )


def serialize_activation_authorization_record(a: ActivationAuthorizationV1) -> bytes:
    body = serialize_activation_authorization_body(a)
    assert len(body) == AUTH_BODY_BYTES
    return body + _require_len("issuer_signature_ed25519", a.issuer_signature_ed25519, SIGNATURE_BYTES)


def serialize_activation_authorization_signed_message(a: ActivationAuthorizationV1) -> bytes:
    return ACTIVATION_AUTH_SIGNED_DOMAIN + serialize_activation_authorization_body(a)


def parse_activation_authorization_record(data: bytes) -> ActivationAuthorizationV1:
    if len(data) < AUTH_RECORD_BYTES:
        raise RecordTooShort(f"activation authorization record is {len(data)} bytes, need {AUTH_RECORD_BYTES}")
    if len(data) > AUTH_RECORD_BYTES:
        raise RecordTooLong(f"activation authorization record is {len(data)} bytes, expected exactly {AUTH_RECORD_BYTES}")
    (transaction_id, grant_digest, prepared_root_digest, revision) = struct.unpack(
        _AUTH_BODY_PREFIX_FORMAT, data[:_AUTH_BODY_PREFIX_BYTES]
    )
    offset = _AUTH_BODY_PREFIX_BYTES
    binding = parse_binding(data[offset:offset + BINDING_BYTES])
    offset += BINDING_BYTES
    (device_fresh_challenge, host_nonce) = struct.unpack(
        _AUTH_BODY_SUFFIX_FORMAT, data[offset:offset + _AUTH_BODY_SUFFIX_BYTES]
    )
    offset += _AUTH_BODY_SUFFIX_BYTES
    signature = data[offset:offset + SIGNATURE_BYTES]
    offset += SIGNATURE_BYTES
    assert offset == AUTH_RECORD_BYTES
    return ActivationAuthorizationV1(
        transaction_id=transaction_id, grant_digest_sha256=grant_digest,
        prepared_root_digest_sha256=prepared_root_digest, spent_authorized_revision=revision,
        expected_binding=binding, device_fresh_challenge=device_fresh_challenge, host_nonce=host_nonce,
        issuer_signature_ed25519=signature,
    )


# AuthorityAckCodec -- Python mirror of AuthorityDeviceSession.h's
# AuthorityAckCodec: the canonical message the device's Ed25519 signature
# actually covers for a prepare-ack vs an activation-ack, so a signed
# prepare acknowledgement can never be replayed as an activation
# acknowledgement (domain separation via the trailing tag byte).
ACK_TAG_PREPARE = 0xA1
ACK_TAG_ACTIVATE = 0xA2
ACK_MESSAGE_BYTES = CHALLENGE_BYTES + CHALLENGE_BYTES + TRANSACTION_ID_BYTES + DIGEST_BYTES + 1
assert ACK_MESSAGE_BYTES == 81, ACK_MESSAGE_BYTES


def _serialize_ack_message(host_challenge: bytes, device_nonce: bytes, transaction_id: bytes, root_digest: bytes,
                            tag: int) -> bytes:
    return (
        _require_len("host_challenge", host_challenge, CHALLENGE_BYTES)
        + _require_len("device_nonce", device_nonce, CHALLENGE_BYTES)
        + _require_len("transaction_id", transaction_id, TRANSACTION_ID_BYTES)
        + _require_len("root_digest", root_digest, DIGEST_BYTES)
        + bytes((tag,))
    )


def serialize_prepare_ack_message(host_challenge: bytes, device_nonce: bytes, transaction_id: bytes,
                                   root_digest: bytes) -> bytes:
    return _serialize_ack_message(host_challenge, device_nonce, transaction_id, root_digest, ACK_TAG_PREPARE)


def serialize_activate_ack_message(host_challenge: bytes, device_nonce: bytes, transaction_id: bytes,
                                    root_digest: bytes) -> bytes:
    return _serialize_ack_message(host_challenge, device_nonce, transaction_id, root_digest, ACK_TAG_ACTIVATE)


PREPARE_ACK_BYTES = CHALLENGE_BYTES + DIGEST_BYTES + SIGNATURE_BYTES
assert PREPARE_ACK_BYTES == 112, PREPARE_ACK_BYTES
ACTIVATE_ACK_BYTES = CHALLENGE_BYTES + SIGNATURE_BYTES
assert ACTIVATE_ACK_BYTES == 80, ACTIVATE_ACK_BYTES


@dataclass
class PreparedRootResponse:
    """Wire mirror of AuthorityDeviceSession.h's PreparedRootResponse --
    exactly ObjectKind.PREPARE_ACK's 112 bytes."""
    device_nonce: bytes
    root_digest_sha256: bytes
    device_signature_ed25519: bytes


def parse_prepared_root_response(data: bytes) -> PreparedRootResponse:
    if len(data) != PREPARE_ACK_BYTES:
        raise (RecordTooShort if len(data) < PREPARE_ACK_BYTES else RecordTooLong)(
            f"prepare ack is {len(data)} bytes, need exactly {PREPARE_ACK_BYTES}"
        )
    return PreparedRootResponse(
        device_nonce=data[:CHALLENGE_BYTES],
        root_digest_sha256=data[CHALLENGE_BYTES:CHALLENGE_BYTES + DIGEST_BYTES],
        device_signature_ed25519=data[CHALLENGE_BYTES + DIGEST_BYTES:],
    )


@dataclass
class ActivationResponse:
    """Wire mirror of AuthorityDeviceSession.h's ActivationResponse --
    exactly ObjectKind.ACTIVATE_ACK's 80 bytes."""
    device_nonce: bytes
    device_signature_ed25519: bytes


def parse_activation_response(data: bytes) -> ActivationResponse:
    if len(data) != ACTIVATE_ACK_BYTES:
        raise (RecordTooShort if len(data) < ACTIVATE_ACK_BYTES else RecordTooLong)(
            f"activate ack is {len(data)} bytes, need exactly {ACTIVATE_ACK_BYTES}"
        )
    return ActivationResponse(
        device_nonce=data[:CHALLENGE_BYTES],
        device_signature_ed25519=data[CHALLENGE_BYTES:],
    )


# ---------------------------------------------------------------------
# MaintenanceSessionClient -- the production host-side driver for a
# single live USB commissioning conversation, built ONLY on Hydra's real
# `ota_maintenance_protocol` encode/decode functions and OBJECT_LENGTHS
# table (never a duplicated constant/parser), over an injected
# `transport` exposing exactly `ota_rf_lab.FramedSerial`'s own
# `.command(payload, expected, timeout) -> bytes` method (the real
# production transport IS an `ota_rf_lab.FramedSerial` instance,
# constructed by the CLI against an explicit `/dev/serial/by-id/...`
# path; tests inject an explicit in-process maintenance-ABI responder
# double that implements the SAME documented sequence below -- never
# real hardware).
#
# IMPORTANT, HONESTLY STATED SCOPE: the exact device-side subcommand
# SEQUENCING semantics (what MEASURE/CERTIFY/PREPARE/ACTIVATE/POLL/
# CHALLENGE/CANCEL actually trigger on a real device) are NOT a
# cross-owner-frozen contract the way the wire SHAPES (headers/object
# lengths/status enums) are -- Hydra's module fixes only the byte-level
# codec. The sequence this client drives (OPEN -> MEASURE -> read
# MEASUREMENT -> upload AUTHORITY_GRANT -> upload PREPARE_AUTHORIZATION
# -> trigger PREPARE -> poll -> read PREPARE_ACK -> read
# PREPARED_ARTIFACT -> CLOSE, and the ACTIVATE mirror of it) is this
# module's own reasoned design, built so that every OBJECT_KIND/status
# it touches matches Hydra's frozen table exactly -- it is NOT yet
# confirmed against FW's actual device-side endpoint (explicitly FW's
# unwired, later integration step). Default-deny applies throughout:
# any reply other than the single expected terminal success shape for
# the step just attempted raises MaintenanceProtocolError rather than
# being treated as a soft/retryable success.
# ---------------------------------------------------------------------


class MaintenanceProtocolError(Exception):
    """Raised on any Maintenance-session reply that is not the single
    expected terminal success shape for the step just attempted --
    Pending/Busy/Denied/OwnershipDenied/Missing/Corrupt/Uncertain/
    ChangedRequest/NoCapacity, a session/request-id/subcommand echo
    mismatch, or any transport/codec exception. Never caught and
    silently retried anywhere in this module except poll_until_terminal's
    own explicit, bounded Pending-tolerant loop."""


class MaintenanceSessionClient:
    """Constructor performs zero I/O (matches every other host-side
    seam in this module); open() is the first real exchange."""

    def __init__(self, transport, timeout: float = 5.0):
        self._transport = transport
        self._timeout = timeout
        self._session = bytes(CHALLENGE_BYTES)
        self._next_id = 1
        # Admitted nonzero logical job ticket, allocated once OPEN
        # assigns a session (see open()) and retained across every
        # subsequent exchange in this job (upload/challenge/trigger/
        # poll/read/cancel) -- per MAIN's concrete adapter correction,
        # sending job_ticket=0 for those calls is a real production bug
        # (the router rejects such job calls); OPEN itself still
        # requires job_ticket=0 (checked below in open()). This is the
        # HOST's own admitted logical job id, never to be confused with
        # internal Store/FW collector-owned device tickets.
        self._job_ticket = 0

    def _alloc_request_id(self) -> int:
        value = self._next_id
        self._next_id += 1
        if self._next_id > 0xFFFFFFFF:
            raise MaintenanceProtocolError("exhausted 32-bit request ids within a single session")
        return value

    def _exchange(self, subcommand, *, object_kind=maint.ObjectKind.NONE, total=0, offset=0, data=b"",
                  data_len=None, session_override=None) -> "maint.Reply":
        request_id = self._alloc_request_id()
        session = session_override if session_override is not None else self._session
        job_ticket = 0 if subcommand == maint.Subcommand.OPEN else self._job_ticket
        request = maint.Request(
            subcommand=subcommand, session=session, request_id=request_id, job_ticket=job_ticket,
            object_kind=object_kind, total=total, offset=offset,
            data_len=(len(data) if data_len is None else data_len), data=data,
        )
        try:
            wire = maint.encode_request(request)
        except maint.MaintenanceCodecError as exc:
            raise MaintenanceProtocolError(f"failed to encode {subcommand.name} request: {exc}") from exc
        try:
            reply_bytes = self._transport.command(wire, expected=(maint.RESPONSE,), timeout=self._timeout)
        except Exception as exc:  # noqa: BLE001 -- any transport failure is a hard session failure
            raise MaintenanceProtocolError(f"transport failure during {subcommand.name}: {exc}") from exc
        try:
            reply = maint.decode_reply(reply_bytes)
        except maint.MaintenanceCodecError as exc:
            raise MaintenanceProtocolError(f"malformed {subcommand.name} reply: {exc}") from exc
        if reply.subcommand != subcommand:
            raise MaintenanceProtocolError(
                f"reply subcommand {reply.subcommand!r} does not match request {subcommand!r}"
            )
        if reply.request_id != request_id:
            raise MaintenanceProtocolError("reply request_id does not echo the request -- never trusted")
        if subcommand != maint.Subcommand.OPEN and reply.session != self._session:
            raise MaintenanceProtocolError("reply session does not match this session -- never trusted")
        return reply

    def open(self, host_challenge: bytes) -> None:
        if self._session != bytes(CHALLENGE_BYTES):
            raise MaintenanceProtocolError("open() called twice on the same MaintenanceSessionClient")
        reply = self._exchange(
            maint.Subcommand.OPEN, total=CHALLENGE_BYTES,
            data=_require_len("host_challenge", host_challenge, CHALLENGE_BYTES),
            session_override=bytes(CHALLENGE_BYTES),
        )
        if reply.status != maint.Status.OK:
            raise MaintenanceProtocolError(f"device refused OPEN: status={reply.status!r} reason={reply.reason!r}")
        if reply.session == bytes(CHALLENGE_BYTES):
            raise MaintenanceProtocolError("device did not assign a nonzero session on OPEN")
        self._session = reply.session
        # Allocate the one admitted nonzero logical job ticket for
        # every exchange for the remainder of this session (upload/
        # challenge/trigger/poll/read/cancel) -- a fresh, non-reused
        # value per MaintenanceSessionClient instance (never 0, since a
        # new session always assigns a new nonzero session id via OPEN
        # and this ticket is derived from it).
        self._job_ticket = int.from_bytes(self._session[:4], "big") or 1

    def require_ok(self, reply: "maint.Reply", step: str) -> "maint.Reply":
        if reply.status != maint.Status.OK:
            raise MaintenanceProtocolError(f"{step} denied by device: status={reply.status!r} reason={reply.reason!r}")
        return reply

    def trigger(self, subcommand) -> "maint.Reply":
        if subcommand == maint.Subcommand.OPEN:
            raise MaintenanceProtocolError("use open() for OPEN, not trigger()")
        return self._exchange(subcommand)

    def poll_until_terminal(self, max_attempts: int = 100, interval_s: float = 0.05) -> "maint.Reply":
        for _ in range(max_attempts):
            reply = self._exchange(maint.Subcommand.POLL)
            if reply.status != maint.Status.PENDING:
                return reply
            time.sleep(interval_s)
        raise MaintenanceProtocolError("device never left Pending within the polling budget")

    def upload_object(self, kind, payload: bytes) -> None:
        total = maint.OBJECT_LENGTHS.get(kind)
        if not total:
            raise MaintenanceProtocolError(f"{kind!r} is not a fixed-length uploadable object")
        if len(payload) != total:
            raise MaintenanceProtocolError(f"{kind!r} payload is {len(payload)} bytes, need exactly {total}")
        offset = 0
        while offset < total:
            chunk = payload[offset:offset + maint.MAX_DATA]
            reply = self._exchange(maint.Subcommand.PUT_FRAGMENT, object_kind=kind, total=total, offset=offset,
                                    data=chunk)
            self.require_ok(reply, f"PUT_FRAGMENT({kind.name}, offset={offset})")
            offset += len(chunk)

    def download_object(self, kind) -> bytes:
        total = maint.OBJECT_LENGTHS.get(kind)
        if not total:
            raise MaintenanceProtocolError(f"{kind!r} is not a fixed-length downloadable object")
        out = bytearray()
        offset = 0
        while offset < total:
            count = min(maint.MAX_DATA, total - offset)
            reply = self._exchange(maint.Subcommand.READ_OBJECT, object_kind=kind, total=total, offset=offset,
                                    data=b"", data_len=count)
            self.require_ok(reply, f"READ_OBJECT({kind.name}, offset={offset})")
            if reply.object_kind != kind or reply.total != total or reply.offset != offset or len(reply.data) != count:
                raise MaintenanceProtocolError(f"READ_OBJECT({kind.name}) reply shape mismatch")
            out += reply.data
            offset += count
        return bytes(out)

    def close(self) -> None:
        self.require_ok(self.trigger(maint.Subcommand.CLOSE), "CLOSE")

    def obtain_device_challenge(self, purpose: int) -> bytes:
        """CHALLENGE (FINAL agreed shape, supersedes the earlier
        purpose-byte-in-data proposal): the EXISTING objectKind field is
        the explicit purpose selector -- object_kind=
        ObjectKind.PREPARE_AUTHORIZATION(4) for a PREPARE job,
        ObjectKind.ACTIVATION_AUTHORIZATION(5) for an ACTIVATE job --
        carrying NO payload (total=offset=data_len=0); kind here selects
        authorization purpose, NOT an uploaded 267-byte object. The
        device replies with exactly 16 bytes of its OWN fresh entropy
        (object_kind=NONE, total=0, offset=0, data_len=16), independent
        of OPEN's host_challenge and MEASUREMENT.device_nonce -- the
        single authoritative challenge owner is this device-session
        continuation, never a second router-local random pool.

        Hydra's maintenance owner has landed the request-side exception
        admitting a nonzero (purpose-selecting) objectKind specifically
        for CHALLENGE in the installed scripts/ota_maintenance_protocol.py
        (`_validate_request` now requires exactly a nonzero job ticket
        plus PREPARE_AUTHORIZATION/ACTIVATION_AUTHORIZATION kind and
        rejects anything else) -- this call is live, real production
        request/reply traffic, not a stub."""
        purpose_kind = {
            int(maint.Subcommand.PREPARE): maint.ObjectKind.PREPARE_AUTHORIZATION,
            int(maint.Subcommand.ACTIVATE): maint.ObjectKind.ACTIVATION_AUTHORIZATION,
        }.get(purpose)
        if purpose_kind is None:
            raise MaintenanceProtocolError(f"unsupported CHALLENGE purpose: {purpose!r}")
        reply = self._exchange(maint.Subcommand.CHALLENGE, object_kind=purpose_kind, total=0, offset=0, data=b"")
        self.require_ok(reply, "CHALLENGE")
        if reply.object_kind != maint.ObjectKind.NONE or reply.total != 0 or reply.offset != 0:
            raise MaintenanceProtocolError("CHALLENGE reply shape does not match the agreed contract")
        if len(reply.data) != CHALLENGE_BYTES:
            raise MaintenanceProtocolError("CHALLENGE reply did not carry exactly 16 bytes")
        return reply.data


def read_device_measurement(session: MaintenanceSessionClient, host_challenge: bytes) -> "maint.Measurement":
    """OPEN(host_challenge) -> trigger MEASURE (ask the device to
    (re)compute a fresh measurement, including its OWN fresh
    device_nonce, for this exact session) -> READ_OBJECT(MEASUREMENT).
    The returned Measurement's `device_nonce` is the device-MINTED
    entropy this module binds PrepareAuthorizationV1.device_fresh_challenge
    to -- never a host-chosen value, closing the Astra section D gap."""
    session.open(host_challenge)
    session.require_ok(session.trigger(maint.Subcommand.MEASURE), "MEASURE")
    blob = session.download_object(maint.ObjectKind.MEASUREMENT)
    try:
        return maint.decode_measurement(blob)
    except maint.MaintenanceCodecError as exc:
        raise MaintenanceProtocolError(f"malformed MEASUREMENT object: {exc}") from exc


def verify_measurement_matches_binding(measurement: "maint.Measurement", binding: AuthorityBinding) -> None:
    """Defense-in-depth cross-check ONLY -- per MAIN's binding
    clarification, a device's self-reported measured fields are NEVER
    themselves the authenticated gate (that remains the signed grant +
    signed device ack); this merely refuses to proceed if the device's
    own report of what it is contradicts the grant about to be staged on
    it, catching an operator/cable mix-up before any registry state
    changes."""
    if measurement.uid8 != binding.hardware_uid:
        raise MaintenanceProtocolError("device-reported uid8 does not match the grant's hardware_uid")
    if measurement.full_public_key != binding.mesh_full_public_key:
        raise MaintenanceProtocolError("device-reported full_public_key does not match the grant's mesh_full_public_key")
    if measurement.profile != binding.profile_id:
        raise MaintenanceProtocolError("device-reported profile does not match the grant's profile_id")
    if measurement.layout != binding.layout_id:
        raise MaintenanceProtocolError("device-reported layout does not match the grant's layout_id")


def verify_measurement_matches_certified_baseline(
    measurement: "maint.Measurement", manifest: BaselineCertificationManifest, certify_binding: AuthorityBinding
) -> None:
    """Sol HIGH2 fix: verify_measurement_matches_binding (above) only
    ever checked UID/fullPK/profile/layout -- it never looked at the
    device's measured IMAGE/SDK/loader/config evidence at all, so a
    device reporting all-zero hashes against a certified baseline with
    real nonzero digests still sailed through to PREPARE/ActivationSpent.
    This closes that gap: the device's self-reported measured image
    hash+extent, its SDK28 digest (cross-checked for genuine
    self-consistency against its own reported raw bytes, not merely
    trusted as an opaque field), its stock-loader evidence, its boot
    config id, and its currently-running compiled role must ALL agree
    with the signed CertifyExistingBaseline evidence (manifest C /
    certify_binding B) BEFORE any device mutation (grant upload, PREPARE
    trigger) or registry spend is attempted. Like
    verify_measurement_matches_binding, this is defense-in-depth on top
    of (never a substitute for) the signed grant + signed device ack;
    any mismatch here is refused outright, never weakened."""
    if measurement.image_sha256 != manifest.approved_image_sha256:
        raise MaintenanceProtocolError("device-measured image_sha256 does not match the certified baseline's approved_image_sha256")
    if measurement.image_address != manifest.approved_image_extent_offset:
        raise MaintenanceProtocolError("device-measured image_address does not match the certified baseline's approved_image_extent_offset")
    if measurement.image_extent != manifest.approved_image_extent_length:
        raise MaintenanceProtocolError("device-measured image_extent does not match the certified baseline's approved_image_extent_length")
    # Self-consistency: a device claiming a specific sdk28_sha256 must
    # actually be reporting the raw bytes that hash to it -- a device
    # that reports a correct-looking digest field without matching raw
    # bytes (or vice-versa) is lying about one of the two, and must be
    # refused regardless of which one happens to match the manifest.
    if hashlib.sha256(measurement.raw_sdk28).digest() != measurement.sdk28_sha256:
        raise MaintenanceProtocolError(
            "device-reported sdk28_sha256 does not match the SHA-256 of the device's own reported raw_sdk28 bytes"
        )
    if measurement.sdk28_sha256 != manifest.expected_sdk28_sha256_digest:
        raise MaintenanceProtocolError("device-measured sdk28_sha256 does not match the certified baseline's expected_sdk28_sha256_digest")
    if measurement.loader_sha256 != manifest.stock_loader_artifact_sha256:
        raise MaintenanceProtocolError("device-measured loader_sha256 does not match the certified baseline's stock_loader_artifact_sha256")
    if measurement.loader_start != manifest.stock_loader_artifact_range_start:
        raise MaintenanceProtocolError("device-measured loader_start does not match the certified baseline's stock_loader_artifact_range_start")
    if measurement.loader_length != manifest.stock_loader_artifact_range_length:
        raise MaintenanceProtocolError("device-measured loader_length does not match the certified baseline's stock_loader_artifact_range_length")
    if measurement.boot_config_id != manifest.boot_config_id:
        raise MaintenanceProtocolError("device-measured boot_config_id does not match the certified baseline's boot_config_id")
    # The EXACT compiled role this device is currently running must
    # agree with the role the baseline certification itself was
    # certified against -- a label/role relabel does NOT make a
    # differently-compiled image usable under a certification it was
    # never actually measured/certified for.
    if measurement.current_role != certify_binding.historical_initial_role_id:
        raise MaintenanceProtocolError(
            "device-measured current_role does not match the CertifyExistingBaseline transaction's "
            "historical_initial_role_id -- the certified baseline evidence does not cover this role"
        )


# ---------------------------------------------------------------------
# Canonical P683 (PREPARED_ARTIFACT) layout + provenance sidecar.
#
# Sol HIGH3 fix: P was previously treated as an OPAQUE 683-byte buffer
# here, with ONLY its SHA-256 commitment (R) checked against the
# device's signed PREPARE_ACK -- an arbitrary 683-byte blob with the
# right length and hash sailed straight through to a durable sidecar
# write and ActivationSpent. A signed R alone proves the device signed
# an ack ABOUT *some* 683-byte buffer; it proves nothing about that
# buffer's actual semantic content/provenance. This module now defines
# the real canonical layout of P (the "fixed first-pair P683 layout",
# per PrepareAuthorizationCodec.h's own doc comment) and fully parses +
# cross-validates it against the exact authorized grant/certify/
# manifest/rx-context/peer-key inputs this handshake itself produced,
# BEFORE any provenance sidecar is written or ActivationSpent is
# committed:
#
#   G238  (0:238)    == serialize_record(grant) -- byte-identical.
#   C238  (238:476)  == serialize_record(certify) -- byte-identical.
#   B117  (476:593)  == serialize_baseline_manifest(manifest) -- byte-identical.
#   rxContextKind(1) (593:594) == int(rx_kind).
#   peerFullPublicKey(32) (594:626) == peer_full_public_key.
#   storeIdentity(16) (626:642) -- device-generated opaque store
#     instance identity; structurally present, never all-zero (a
#     genuinely-initialized store always has one).
#   sdk28Sha256(32) (642:674) == manifest.expected_sdk28_sha256_digest
#     (cross-checked against the measurement's own self-consistent
#     digest too, closing the same lying-digest gap as HIGH2).
#   txUpperBound(4, BE) (674:678) == grant.initial_tx_sequence_floor --
#     the exact initial TX context floor this P was staged against.
#   genesisFloor(4, BE) (678:682) == grant.initial_rx_replay_floor --
#     the exact initial RX replay floor (genesis) this P was staged
#     against.
#   watermark(1) (682:683) == kPreparedArtifactWatermark, a fixed
#     constant marking this as a genuine PreparedArtifactV1 encoding
#     (never a stray/foreign blob that merely happens to be 683 bytes).
#
# Note this is the exact same first 626 bytes as
# build_prepare_authorization_input_bytes()/PREPARE_INPUT -- reused
# directly below rather than re-derived, so a divergence there is
# structurally impossible.
#
# Still never produced by real Store/Firmware integration here (this
# module holds no actual on-device storage); the first-use serializer
# below exists purely so this host-side verifier has a genuine,
# independent fixture to validate against in tests, and so a real
# device/store implementation has an exact canonical target to conform
# to -- never a pretend/placeholder shape.
# ---------------------------------------------------------------------

PREPARED_ARTIFACT_WATERMARK = 0x5A
PREPARED_ARTIFACT_STORE_IDENTITY_BYTES = 16
_PREPARED_ARTIFACT_TAIL_FORMAT = ">16s32sIIB"
PREPARED_ARTIFACT_TAIL_BYTES = struct.calcsize(_PREPARED_ARTIFACT_TAIL_FORMAT)
assert PREPARED_ARTIFACT_TAIL_BYTES == 57, PREPARED_ARTIFACT_TAIL_BYTES
assert PREPARE_AUTH_INPUT_DIGEST_SOURCE_BYTES + PREPARED_ARTIFACT_TAIL_BYTES == 683, (
    PREPARE_AUTH_INPUT_DIGEST_SOURCE_BYTES + PREPARED_ARTIFACT_TAIL_BYTES
)


class PreparedArtifactCodecError(AuthorityCodecError):
    """Raised by parse_prepared_artifact on any malformed/truncated/
    wrong-watermark P683 buffer -- never partially trusted."""


@dataclass
class PreparedArtifactV1:
    grant: AuthorityTransaction
    certify: AuthorityTransaction
    manifest: BaselineCertificationManifest
    rx_kind: "PrepareRxContextKind"
    peer_full_public_key: bytes
    store_identity: bytes
    sdk28_sha256: bytes
    tx_upper_bound: int
    genesis_floor: int


def serialize_prepared_artifact(p: PreparedArtifactV1) -> bytes:
    """Builds the real, genuine 683-byte P683 encoding -- used both by
    this module's own tests (as an independent fixture a real
    device/store must conform to) and as the canonical reference a real
    integrator's device-side serializer must byte-match."""
    head = build_prepare_authorization_input_bytes(p.grant, p.certify, p.manifest, p.rx_kind, p.peer_full_public_key)
    tail = struct.pack(
        _PREPARED_ARTIFACT_TAIL_FORMAT,
        _require_len("store_identity", p.store_identity, PREPARED_ARTIFACT_STORE_IDENTITY_BYTES),
        _require_len("sdk28_sha256", p.sdk28_sha256, DIGEST_BYTES),
        p.tx_upper_bound,
        p.genesis_floor,
        PREPARED_ARTIFACT_WATERMARK,
    )
    buf = head + tail
    assert len(buf) == maint.OBJECT_LENGTHS[maint.ObjectKind.PREPARED_ARTIFACT]
    return buf


def parse_prepared_artifact(blob: bytes) -> PreparedArtifactV1:
    """Fails closed on any malformed/truncated/wrong-length/wrong-
    watermark input -- never returns a partially-trusted result."""
    expected_len = maint.OBJECT_LENGTHS[maint.ObjectKind.PREPARED_ARTIFACT]
    if len(blob) != expected_len:
        raise PreparedArtifactCodecError(f"PREPARED_ARTIFACT is {len(blob)} bytes, need exactly {expected_len}")
    try:
        grant = parse_record(blob[0:RECORD_BYTES])
        certify = parse_record(blob[RECORD_BYTES:2 * RECORD_BYTES])
        manifest_bytes = blob[2 * RECORD_BYTES:2 * RECORD_BYTES + BASELINE_MANIFEST_BYTES]
        manifest = parse_baseline_manifest(manifest_bytes)
    except AuthorityCodecError as exc:
        raise PreparedArtifactCodecError(f"malformed G238/C238/B117 region: {exc}") from exc
    off = 2 * RECORD_BYTES + BASELINE_MANIFEST_BYTES
    rx_kind_byte = blob[off]
    off += 1
    peer_full_public_key = blob[off:off + PUBLIC_KEY_BYTES]
    off += PUBLIC_KEY_BYTES
    if off != PREPARE_AUTH_INPUT_DIGEST_SOURCE_BYTES:
        raise PreparedArtifactCodecError("internal offset mismatch parsing G238/C238/B117 head")
    try:
        rx_kind = PrepareRxContextKind(rx_kind_byte)
    except ValueError as exc:
        raise PreparedArtifactCodecError(f"invalid rxContextKind byte {rx_kind_byte!r}") from exc
    store_identity, sdk28_sha256, tx_upper_bound, genesis_floor, watermark = struct.unpack_from(
        _PREPARED_ARTIFACT_TAIL_FORMAT, blob, off
    )
    if watermark != PREPARED_ARTIFACT_WATERMARK:
        raise PreparedArtifactCodecError(f"PREPARED_ARTIFACT watermark byte is {watermark!r}, expected {PREPARED_ARTIFACT_WATERMARK!r}")
    return PreparedArtifactV1(
        grant=grant, certify=certify, manifest=manifest, rx_kind=rx_kind,
        peer_full_public_key=bytes(peer_full_public_key), store_identity=bytes(store_identity),
        sdk28_sha256=bytes(sdk28_sha256), tx_upper_bound=tx_upper_bound, genesis_floor=genesis_floor,
    )


def verify_prepared_artifact_semantics(
    parsed: PreparedArtifactV1, grant: AuthorityTransaction, certify: AuthorityTransaction,
    manifest: BaselineCertificationManifest, rx_kind: "PrepareRxContextKind", peer_full_public_key: bytes,
    measurement: "maint.Measurement",
) -> None:
    """Cross-validates a parsed PREPARED_ARTIFACT against the EXACT
    authorized inputs this handshake itself produced -- a header-only-
    correct or signed-but-semantically-wrong P683 (e.g. a prepared
    artifact genuinely belonging to a DIFFERENT grant/certify/manifest
    whose SHA-256 happened to be re-signed, or simply a stale one from a
    previous attempt) must be refused BEFORE any sidecar write or
    ActivationSpent commit, exactly like the measurement/binding checks
    above."""
    if serialize_record(parsed.grant) != serialize_record(grant):
        raise MaintenanceProtocolError("PREPARED_ARTIFACT's embedded grant record (G238) does not match the authorized grant")
    if serialize_record(parsed.certify) != serialize_record(certify):
        raise MaintenanceProtocolError("PREPARED_ARTIFACT's embedded certify record (C238) does not match the authorized CertifyExistingBaseline transaction")
    if serialize_baseline_manifest(parsed.manifest) != serialize_baseline_manifest(manifest):
        raise MaintenanceProtocolError("PREPARED_ARTIFACT's embedded baseline manifest (B117) does not match the authorized manifest")
    if parsed.rx_kind != rx_kind:
        raise MaintenanceProtocolError("PREPARED_ARTIFACT's rxContextKind does not match the authorized PREPARE_INPUT's rx_kind")
    if parsed.peer_full_public_key != peer_full_public_key:
        raise MaintenanceProtocolError("PREPARED_ARTIFACT's peerFullPublicKey does not match the authorized PREPARE_INPUT's peer key")
    if all(b == 0 for b in parsed.store_identity):
        raise MaintenanceProtocolError("PREPARED_ARTIFACT's storeIdentity is all-zero -- never a genuinely-initialized store")
    if parsed.sdk28_sha256 != manifest.expected_sdk28_sha256_digest:
        raise MaintenanceProtocolError("PREPARED_ARTIFACT's sdk28Sha256 does not match the certified baseline's expected_sdk28_sha256_digest")
    if parsed.sdk28_sha256 != measurement.sdk28_sha256:
        raise MaintenanceProtocolError("PREPARED_ARTIFACT's sdk28Sha256 does not match this session's own measured sdk28_sha256")
    if parsed.tx_upper_bound != grant.initial_tx_sequence_floor:
        raise MaintenanceProtocolError("PREPARED_ARTIFACT's txUpperBound does not match the authorized grant's initial_tx_sequence_floor")
    if parsed.genesis_floor != grant.initial_rx_replay_floor:
        raise MaintenanceProtocolError("PREPARED_ARTIFACT's genesisFloor does not match the authorized grant's initial_rx_replay_floor")


class ProvenanceSidecarError(Exception):
    pass


def _provenance_sidecar_path(registry_path: Path, transaction_id: bytes) -> Path:
    return registry_path.parent / f"{registry_path.name}.prepared-artifact-{transaction_id.hex()}.bin"


def write_prepared_artifact_provenance(registry_path: Path, transaction_id: bytes, prepared_artifact: bytes,
                                        prepare_ack_record: bytes,
                                        *, fsync_fault_for_tests: Optional[Callable[[], None]] = None) -> Path:
    """Durably, exclusively (never overwritten -- a second attempt for
    the SAME transaction id is refused outright) writes
    transaction_id(16) + len(prepared_artifact) framed as a fixed
    683-byte block + the 112-byte PREPARE_ACK record beside
    `registry_path`, fsyncing the file AND its parent directory before
    returning -- mirrors the registry copies' own two-step durability
    discipline (_fsync_parent_directory).

    `fsync_fault_for_tests`, FOR TESTS ONLY (mirrors
    AuthorityRegistryCopy.fsync_parent_directory_override_for_tests'
    "simulate a crash at this exact point" convention): if given, it is
    called immediately BEFORE the content fsync and may raise to
    genuinely simulate a crash after the full payload was written into
    the OS page cache but before it (or the parent directory entry) was
    ever confirmed durable -- real production code never passes this."""
    if len(prepared_artifact) != maint.OBJECT_LENGTHS[maint.ObjectKind.PREPARED_ARTIFACT]:
        raise ProvenanceSidecarError(
            f"prepared_artifact is {len(prepared_artifact)} bytes, need exactly "
            f"{maint.OBJECT_LENGTHS[maint.ObjectKind.PREPARED_ARTIFACT]}"
        )
    if len(prepare_ack_record) != PREPARE_ACK_BYTES:
        raise ProvenanceSidecarError(f"prepare_ack_record is {len(prepare_ack_record)} bytes, need {PREPARE_ACK_BYTES}")
    path = _provenance_sidecar_path(registry_path, transaction_id)
    payload = _require_len("transaction_id", transaction_id, TRANSACTION_ID_BYTES) + prepared_artifact + prepare_ack_record
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ProvenanceSidecarError(
            f"refusing to overwrite an existing prepared-artifact provenance sidecar: {path}"
        ) from exc
    try:
        written = 0
        while written < len(payload):
            written += os.write(fd, payload[written:])
        if fsync_fault_for_tests is not None:
            fsync_fault_for_tests()
        os.fsync(fd)
    finally:
        os.close(fd)
    if not _fsync_parent_directory(path):
        raise ProvenanceSidecarError(f"failed to fsync the parent directory of {path}")
    return path


def ensure_prepared_artifact_provenance(registry_path: Path, transaction_id: bytes, prepared_artifact: bytes,
                                         prepare_ack_record: bytes,
                                         *, fsync_fault_for_tests: Optional[Callable[[], None]] = None) -> Path:
    """Sol MEDIUM4 fix: idempotent/crash-resumable wrapper around
    write_prepared_artifact_provenance. A real crash/power-cut can land
    between the TWO registry copies' sidecar writes (copy A durably
    written, copy B never attempted) -- a naive retry blindly re-calling
    the O_EXCL writer for copy A would be refused outright
    (FileExistsError), denying an otherwise-legitimate resume and
    stranding copy B forever.

    If a sidecar already exists for this exact transaction_id, it is
    read back and must hold EXACTLY the same prepared_artifact +
    prepare_ack_record bytes this attempt is about to write -- the SAME
    semantic P/G/C/B/txn/R evidence already durably reconciled, never a
    silent overwrite of DIFFERENT content. A genuinely DIVERGENT existing
    sidecar is refused outright (never repaired/replaced/superseded): the
    first durably-recorded provenance always wins, and a fresh retry's
    legitimately-different challenge/ACK bytes must still resolve to the
    SAME reconciled artifact/ack before this is ever called -- a true
    mismatch here is a hard denial with zero further state-machine
    progress."""
    path = _provenance_sidecar_path(registry_path, transaction_id)
    if path.exists():
        existing_artifact, existing_ack = read_prepared_artifact_provenance(registry_path, transaction_id)
        if existing_artifact != prepared_artifact or existing_ack != prepare_ack_record:
            raise ProvenanceSidecarError(
                f"existing prepared-artifact provenance sidecar {path} holds DIFFERENT evidence than this "
                "attempt -- refusing to silently replace it; the first durably-recorded provenance always "
                "wins and this divergence must be investigated, never papered over with a fresh write"
            )
        return path
    return write_prepared_artifact_provenance(
        registry_path, transaction_id, prepared_artifact, prepare_ack_record,
        fsync_fault_for_tests=fsync_fault_for_tests,
    )


def read_prepared_artifact_provenance(registry_path: Path, transaction_id: bytes) -> Tuple[bytes, bytes]:
    """Fresh cold readback (always reopens from disk) of a previously
    written sidecar -- `(prepared_artifact, prepare_ack_record)`."""
    path = _provenance_sidecar_path(registry_path, transaction_id)
    data = path.read_bytes()
    expected_len = TRANSACTION_ID_BYTES + maint.OBJECT_LENGTHS[maint.ObjectKind.PREPARED_ARTIFACT] + PREPARE_ACK_BYTES
    if len(data) != expected_len:
        raise ProvenanceSidecarError(f"provenance sidecar {path} is {len(data)} bytes, expected exactly {expected_len}")
    stored_txn_id = data[:TRANSACTION_ID_BYTES]
    if stored_txn_id != transaction_id:
        raise ProvenanceSidecarError(f"provenance sidecar {path} transaction_id does not match")
    artifact_end = TRANSACTION_ID_BYTES + maint.OBJECT_LENGTHS[maint.ObjectKind.PREPARED_ARTIFACT]
    return data[TRANSACTION_ID_BYTES:artifact_end], data[artifact_end:]


# ---------------------------------------------------------------------
# BootFloorActivationReceiptV1 -- Python mirror of
# src/ota/authority/BootFloorActivationReceipt.h's canonical ROOT/Boot
# (owner65278) V1 wire format, for cross-language (C bootloader / Python
# / C++) interop TEST-vector verification only. This module never
# writes to boot-owned flash, never parses LittleFS, and holds no
# production publisher key -- it exists solely so a real openssl-backed
# Ed25519 signature produced against a fixed canonical body (using a
# synthetic, ephemeral .tmp-scoped TEST key) can be independently
# recomputed/verified byte-for-byte from Python, matching the C++
# BootFloorActivationReceiptCodec exactly (same offsets, same explicit
# little-endian widths, same CRC32, same domain-prefixed SHA-256 digest
# convention). The authoritative magic value below is COPIED verbatim
# from the Boot owner's own published C header
# (bootloader/xiao_nrf52840_ota/include/xiao_ota_record.h,
# XIAO_OTA_FLOOR_ACTIVATION_MAGIC) -- never re-derived from an ASCII
# mnemonic.
BOOT_FLOOR_RECORD_MAGIC = 0x58464152
BOOT_FLOOR_FIXED_DOMAIN = 0x424F4F54  # ASCII "BOOT", fixed for every device -- never derived.
BOOT_FLOOR_CURRENT_RECORD_VERSION = 1
BOOT_FLOOR_PUBLISHER_FINGERPRINT_BYTES = 32
BOOT_FLOOR_BASELINE_IMAGE_DIGEST_BYTES = 32
BOOT_FLOOR_ORIGINAL_SDK28_DIGEST_BYTES = 32
BOOT_FLOOR_SIGNED_DOMAIN = b"MeshCore/OTA/publisher-floor-activation/v1"
assert len(BOOT_FLOOR_SIGNED_DOMAIN) == 42, len(BOOT_FLOOR_SIGNED_DOMAIN)

# Explicit little-endian struct format for the 322-byte body (everything
# up to, but excluding, the 64-byte trailing signature), mirroring
# BootFloorActivationReceiptCodec::serializeBody field-for-field:
#   magic(4) version(2) recordBytesTotal(2) bootDomain(4) uidNumeric(8)
#   localPk(32) consentOwner(32) target(4) profile(4) layout(4) role(4)
#   publisherKeyId(2) publisherFingerprint(32) hostTxnId(16)
#   authorityTxnDigest(32) manifestDigest(32) preparedRootDigest(32)
#   floor(4) baselineImageSha256(32) baselineExtentLength(4)
#   originalSdk28Sha256(32) crc32(4).
BOOT_FLOOR_BODY_BYTES = 322
BOOT_FLOOR_RECORD_BYTES = BOOT_FLOOR_BODY_BYTES + SIGNATURE_BYTES
assert BOOT_FLOOR_RECORD_BYTES == 386, BOOT_FLOOR_RECORD_BYTES


@dataclass
class BootFloorActivationReceiptV1:
    hardware_uid: bytes = bytes(HARDWARE_UID_BYTES)  # Big-endian, same convention as AuthorityBinding.hardware_uid.
    local_mesh_full_public_key: bytes = bytes(PUBLIC_KEY_BYTES)
    consent_owner_public_key: bytes = bytes(PUBLIC_KEY_BYTES)
    target_id: int = 0
    profile_id: int = 0
    layout_id: int = 0
    current_role: int = 0  # Genesis role: 0 (companion) or 1 (repeater); codec is a pure mirror and does
                            # not itself enforce the range -- that enforcement lives in the C++
                            # BootFloorActivationReceiptExporter, the sole real genesis-issuing authority.
    publisher_key_id: int = 0
    publisher_key_fingerprint_sha256: bytes = bytes(BOOT_FLOOR_PUBLISHER_FINGERPRINT_BYTES)
    host_transaction_id: bytes = bytes(TRANSACTION_ID_BYTES)
    authority_transaction_digest_sha256: bytes = bytes(DIGEST_BYTES)  # A.
    commission_manifest_digest_sha256: bytes = bytes(DIGEST_BYTES)  # M.
    prepared_root_digest_sha256: bytes = bytes(DIGEST_BYTES)  # R.
    floor: int = 0  # MUST be 0 (genesis only).
    baseline_image_sha256: bytes = bytes(BOOT_FLOOR_BASELINE_IMAGE_DIGEST_BYTES)
    baseline_extent_length: int = 0
    original_sdk28_sha256_digest: bytes = bytes(BOOT_FLOOR_ORIGINAL_SDK28_DIGEST_BYTES)
    signature_ed25519: bytes = bytes(SIGNATURE_BYTES)


def _boot_floor_uid_numeric(hardware_uid: bytes) -> int:
    """Big-endian byte-string -> plain numeric decode, mirroring
    BootFloorActivationReceiptCodec::decodeUidBigEndian exactly (never a
    raw memcpy/reinterpret -- the wire format is little-endian, so the
    numeric value is re-encoded below via a genuine '<Q' pack)."""
    return int.from_bytes(hardware_uid, byteorder="big", signed=False)


def serialize_boot_floor_body(r: BootFloorActivationReceiptV1) -> bytes:
    prefix = struct.pack(
        "<IHHIQ",
        BOOT_FLOOR_RECORD_MAGIC,
        BOOT_FLOOR_CURRENT_RECORD_VERSION,
        BOOT_FLOOR_RECORD_BYTES,
        BOOT_FLOOR_FIXED_DOMAIN,
        _boot_floor_uid_numeric(_require_len("hardware_uid", r.hardware_uid, HARDWARE_UID_BYTES)),
    )
    middle = struct.pack(
        "<32s32sIIIIH32s16s32s32s32sI32sI32s",
        _require_len("local_mesh_full_public_key", r.local_mesh_full_public_key, PUBLIC_KEY_BYTES),
        _require_len("consent_owner_public_key", r.consent_owner_public_key, PUBLIC_KEY_BYTES),
        r.target_id,
        r.profile_id,
        r.layout_id,
        r.current_role,
        r.publisher_key_id,
        _require_len(
            "publisher_key_fingerprint_sha256",
            r.publisher_key_fingerprint_sha256,
            BOOT_FLOOR_PUBLISHER_FINGERPRINT_BYTES,
        ),
        _require_len("host_transaction_id", r.host_transaction_id, TRANSACTION_ID_BYTES),
        _require_len("authority_transaction_digest_sha256", r.authority_transaction_digest_sha256, DIGEST_BYTES),
        _require_len("commission_manifest_digest_sha256", r.commission_manifest_digest_sha256, DIGEST_BYTES),
        _require_len("prepared_root_digest_sha256", r.prepared_root_digest_sha256, DIGEST_BYTES),
        r.floor,
        _require_len("baseline_image_sha256", r.baseline_image_sha256, BOOT_FLOOR_BASELINE_IMAGE_DIGEST_BYTES),
        r.baseline_extent_length,
        _require_len(
            "original_sdk28_sha256_digest", r.original_sdk28_sha256_digest, BOOT_FLOOR_ORIGINAL_SDK28_DIGEST_BYTES
        ),
    )
    pre_crc = prefix + middle
    if len(pre_crc) != BOOT_FLOOR_BODY_BYTES - 4:
        raise AuthorityCodecError(f"boot floor pre-CRC body length mismatch: {len(pre_crc)}")
    crc = zlib.crc32(pre_crc) & 0xFFFFFFFF
    body = pre_crc + struct.pack("<I", crc)
    if len(body) != BOOT_FLOOR_BODY_BYTES:
        raise AuthorityCodecError(f"boot floor body length mismatch: {len(body)}")
    return body


def serialize_boot_floor_record(r: BootFloorActivationReceiptV1) -> bytes:
    record = serialize_boot_floor_body(r) + _require_len(
        "signature_ed25519", r.signature_ed25519, SIGNATURE_BYTES
    )
    if len(record) != BOOT_FLOOR_RECORD_BYTES:
        raise AuthorityCodecError(f"boot floor record length mismatch: {len(record)}")
    return record


def compute_boot_floor_signed_digest(r: BootFloorActivationReceiptV1) -> bytes:
    """Real SHA-256 over (fixed 42-byte domain literal, NO trailing NUL)
    || (322-byte canonical body, including its own CRC32) -- the 32-byte
    result is what gets Ed25519-signed/verified as the PLAIN (non-
    prehash) message, matching
    BootFloorActivationReceiptCodec::computeSignedDigest exactly."""
    body = serialize_boot_floor_body(r)
    return hashlib.sha256(BOOT_FLOOR_SIGNED_DOMAIN + body).digest()


def parse_boot_floor_record(record: bytes) -> BootFloorActivationReceiptV1:
    """Fails closed (explicit AuthorityCodecError) on any malformed/
    truncated/wrong-magic/wrong-domain/wrong-CRC input -- mirrors
    BootFloorActivationReceiptCodec::parseRecord's discipline."""
    if len(record) != BOOT_FLOOR_RECORD_BYTES:
        raise AuthorityCodecError(f"boot floor record must be exactly {BOOT_FLOOR_RECORD_BYTES} bytes")
    stored_crc = struct.unpack_from("<I", record, 318)[0]
    computed_crc = zlib.crc32(record[:318]) & 0xFFFFFFFF
    if stored_crc != computed_crc:
        raise AuthorityCodecError("boot floor record CRC32 mismatch")
    magic, version, record_bytes_field, boot_domain, uid_numeric = struct.unpack_from("<IHHIQ", record, 0)
    if magic != BOOT_FLOOR_RECORD_MAGIC:
        raise AuthorityCodecError("boot floor record magic mismatch")
    if version != BOOT_FLOOR_CURRENT_RECORD_VERSION:
        raise AuthorityCodecError("boot floor record version mismatch")
    if record_bytes_field != BOOT_FLOOR_RECORD_BYTES:
        raise AuthorityCodecError("boot floor record self-described length mismatch")
    if boot_domain != BOOT_FLOOR_FIXED_DOMAIN:
        raise AuthorityCodecError("boot floor record domain mismatch")
    hardware_uid = uid_numeric.to_bytes(HARDWARE_UID_BYTES, byteorder="big", signed=False)
    (
        local_pk,
        consent_owner,
        target_id,
        profile_id,
        layout_id,
        current_role,
        publisher_key_id,
        publisher_fp,
        host_txn_id,
        authority_digest,
        manifest_digest,
        prepared_root_digest,
        floor,
        baseline_image,
        baseline_extent_length,
        original_sdk28,
    ) = struct.unpack_from("<32s32sIIIIH32s16s32s32s32sI32sI32s", record, 20)
    signature = record[322:386]
    return BootFloorActivationReceiptV1(
        hardware_uid=hardware_uid,
        local_mesh_full_public_key=local_pk,
        consent_owner_public_key=consent_owner,
        target_id=target_id,
        profile_id=profile_id,
        layout_id=layout_id,
        current_role=current_role,
        publisher_key_id=publisher_key_id,
        publisher_key_fingerprint_sha256=publisher_fp,
        host_transaction_id=host_txn_id,
        authority_transaction_digest_sha256=authority_digest,
        commission_manifest_digest_sha256=manifest_digest,
        prepared_root_digest_sha256=prepared_root_digest,
        floor=floor,
        baseline_image_sha256=baseline_image,
        baseline_extent_length=baseline_extent_length,
        original_sdk28_sha256_digest=original_sdk28,
        signature_ed25519=signature,
    )


# ---------------------------------------------------------------------
# Operator CLI.
# ---------------------------------------------------------------------


def _hex_bytes(value: str, expected_len: int, name: str) -> bytes:
    """Called directly from the subcommand handlers below (never wired
    in as an argparse `type=`), so failures here must surface as the
    same explicit CLI diagnostic (SystemExit with a message) as every
    other operator-facing validation in this module -- never a raw
    traceback."""
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise SystemExit(f"{name} must be hex-encoded bytes") from exc
    if len(raw) != expected_len:
        raise SystemExit(f"{name} must decode to exactly {expected_len} bytes")
    return raw


def _cmd_generate_issuer_key(args: argparse.Namespace) -> int:
    private_path, public_path = generate_issuer_keypair(Path(args.key_dir), name=args.name)
    public_raw = read_raw_public_key(public_path)
    print(f"private key: {private_path}")
    print(f"public key:  {public_path}")
    print(f"public key (raw hex): {public_raw.hex()}")
    return 0


def _chains_from_predecessor(candidate: AuthorityTransaction, predecessor: AuthorityTransaction) -> bool:
    """Mirrors AuthorityCoordinator::chainsFromPredecessor: a strict
    single-step revision advance from the EXACT predecessor transaction
    id -- never an operator-supplied arbitrary revision/predecessor."""
    if candidate.revision != predecessor.revision + 1:
        return False
    return candidate.predecessor_transaction_id == predecessor.transaction_id


class CrossProcessRegistryPairLock:
    """Sol fe862c8 review, H2, then Sol39 review, H3: an EARLIER version
    of this class derived a single lock-file path from the
    lexicographically-smaller of the two registry paths
    (".authority-pair.lock") -- a comment here falsely claimed this was
    "the exact same derivation" as the C++ side and that no further
    Python work was needed. BOTH claims were wrong, and the scheme had
    the SAME root defect Sol39 H2 found in the C++ original: two PAIRS
    that share exactly one common copy -- e.g. (A, B) and (B, C) -- each
    derive their OWN independent min(path) lock file, so the two pairs
    never actually serialize against each other despite both mutating
    B's ownership history.

    This version instead flocks the ACTUAL registry copy files directly
    (O_CREAT|O_RDWR, NEVER O_TRUNC -- a crash safely drops the OS-held
    flock, and the copy's real content is never touched by lock
    bookkeeping), ordered by the opened descriptors' true (st_dev,
    st_ino) identity -- never a path string -- exactly mirroring
    src/ota/authority/AuthorityCrossProcessLock.h's
    FileAuthorityCrossProcessLock. This is what actually makes
    overlapping pairs, reversed argument order, and symlink/hardlink
    aliases of the same underlying file all serialize correctly: dev+ino
    is the one identity that survives all of those, and both copies' fds
    are opened before any ordering decision is made, so there is no
    window in which "determine identity" and "open" could diverge.

    The on-disk LOCK PROTOCOL (which real files get flock()'d, in which
    order) is behaviorally compatible with the C++ side -- both lock the
    real registry copy files by (dev, ino) order -- but the two
    languages' registries are independent storage formats (SQLite vs.
    fixed-width binary slots); this class does not and must not assume
    byte-identical files, only equivalent flock() targets and ordering
    semantics."""

    def __init__(self, registry_a_path: Path, registry_b_path: Path) -> None:
        self._paths = [Path(registry_a_path), Path(registry_b_path)]
        self._fds: list = []

    def __enter__(self) -> "CrossProcessRegistryPairLock":
        opened = []  # List[(fd, dev, ino)]
        try:
            for path in self._paths:
                fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
                st = os.fstat(fd)
                opened.append((fd, st.st_dev, st.st_ino))
        except OSError:
            for fd, _dev, _ino in opened:
                os.close(fd)
            raise

        # Dedupe aliases (same copy reached via two different path
        # spellings, or a genuine hardlink of the same inode in a
        # different directory) by (dev, ino) BEFORE locking.
        unique = []
        for fd, dev, ino in opened:
            if any(dev == u_dev and ino == u_ino for _u_fd, u_dev, u_ino in unique):
                os.close(fd)  # Redundant fd for an already-represented physical file.
                continue
            unique.append((fd, dev, ino))

        # Globally stable order by true (dev, ino) identity -- never by
        # path string -- so overlapping/aliased pairs constructed by
        # different callers always lock in the SAME order, regardless of
        # which language or which argument order constructed them.
        unique.sort(key=lambda item: (item[1], item[2]))

        locked_fds = []
        try:
            for fd, _dev, _ino in unique:
                fcntl.flock(fd, fcntl.LOCK_EX)
                locked_fds.append(fd)
        except OSError:
            for fd in locked_fds:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            for fd, _dev, _ino in unique:
                if fd not in locked_fds:
                    os.close(fd)
            raise

        self._fds = locked_fds
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        for fd in self._fds:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        self._fds = []


# ---------------------------------------------------------------------
# commission-existing / resume-commission / inspect-commission -- the
# real host-side Prepare handshake driver over an actual USB Maintenance
# session, reusing Hydra's frozen codec and the existing FramedSerial
# transport directly (never duplicated). Ends at a durable
# ActivationSpent commit on BOTH registry copies (the ACTUAL
# commitment/permission-release point per Astra section 5) -- it does
# NOT perform the separate on-device ACTIVATE exchange (which, per
# Astra section 6, consumes NO further registry write and is
# deliberately left as a flagged remaining gap rather than a pretend
# "also activates" shortcut here).
# ---------------------------------------------------------------------


def _verify_still_lineage_tip(pair: AuthorityRegistryPair, grant: AuthorityTransaction, transaction_id: bytes) -> None:
    """Re-validates BOTH ownership and physical lineage immediately
    before a durable state-advancing write. Required at EVERY such
    point in the handshake (both before the ConsumedPrepared commit AND
    again immediately before the final ActivationSpent commit), never
    just once at entry -- mirrors AuthorityCoordinator's own repeated
    lineage reconfirmation discipline (H3/Sol43 residual fixes). Refuses
    outright unless this exact transaction_id is still the tip of BOTH
    lineage views."""
    for check in (pair.reconcile_ownership_lineage, pair.reconcile_physical_lineage):
        lineage = check(grant.binding)
        if lineage.outcome == ReconciliationOutcome.UNCERTAIN:
            raise SystemExit(
                "refusing to proceed: registry copies disagree about this transaction's lineage "
                "-- reconcile/repair the registries before continuing"
            )
        if lineage.outcome == ReconciliationOutcome.NOT_FOUND:
            raise SystemExit(
                "refusing to proceed: this transaction's lineage is no longer found in either registry copy"
            )
        assert lineage.resolved is not None
        if lineage.resolved.txn.transaction_id != transaction_id:
            raise SystemExit(
                "refusing to proceed: a DIFFERENT transaction is now the lineage tip for this ownership/"
                "physical-device identity -- a competing fork was committed concurrently, never silently continue"
            )


def _baseline_manifest_from_args(args: argparse.Namespace) -> BaselineCertificationManifest:
    """Same field shape as `compute-baseline-manifest-digest` -- the raw
    B field VALUES (not merely its digest) are required to reconstruct
    the exact 626-byte PrepareAuthorizationV1 input-digest source; the
    operator supplies the same evidence here that was used to issue the
    CertifyExistingBaseline grant being referenced."""
    return BaselineCertificationManifest(
        approved_image_sha256=_hex_bytes(args.approved_image_sha256, BASELINE_IMAGE_DIGEST_BYTES,
                                          "--approved-image-sha256"),
        approved_image_extent_offset=args.approved_image_extent_offset,
        approved_image_extent_length=args.approved_image_extent_length,
        expected_sdk28_sha256_digest=_hex_bytes(args.expected_sdk28_sha256_digest, BASELINE_SDK_DIGEST_BYTES,
                                                 "--expected-sdk28-sha256-digest"),
        stock_loader_artifact_sha256=_hex_bytes(args.stock_loader_artifact_sha256,
                                                 BASELINE_STOCK_LOADER_DIGEST_BYTES,
                                                 "--stock-loader-artifact-sha256"),
        stock_loader_artifact_range_start=args.stock_loader_artifact_range_start,
        stock_loader_artifact_range_length=args.stock_loader_artifact_range_length,
        boot_config_id=args.boot_config_id,
        allow_ordinary_userdata=args.allow_ordinary_userdata,
    )


def _default_transport_factory(serial_path: str, work_dir: Path) -> object:
    """Real production transport: ota_rf_lab.FramedSerial against an
    explicit operator-supplied /dev/serial/by-id/... path (its own
    constructor refuses anything else), with its evidence log written
    under the explicit --work-dir (never /tmp). Tests inject an
    explicit in-process fake responder via `transport_factory` instead
    -- never real hardware is driven by this module's own test suite."""
    evidence = ota_rf_lab.Evidence(work_dir / "serial-evidence")
    return ota_rf_lab.FramedSerial("authority", serial_path, evidence)


def _run_prepare_handshake(
    args: argparse.Namespace, *, resuming: bool,
    transport_factory: Optional[Callable[[str], object]] = None,
) -> int:
    registry_a = Path(args.registry_a)
    registry_b = Path(args.registry_b)
    transaction_id = _hex_bytes(args.transaction_id, TRANSACTION_ID_BYTES, "--transaction-id")

    registry_lock = CrossProcessRegistryPairLock(registry_a, registry_b)
    registry_lock.__enter__()
    try:
        pair = AuthorityRegistryPair(AuthorityRegistryCopy(registry_a), AuthorityRegistryCopy(registry_b))

        result = pair.reconcile(transaction_id)
        if result.outcome != ReconciliationOutcome.AGREED or result.resolved is None:
            raise SystemExit(
                f"refusing to prepare: registries are not in an AGREED state for --transaction-id "
                f"(outcome={result.outcome.name}) -- corrupt/disagreeing/missing history is never resumable"
            )
        record = result.resolved
        grant = record.txn

        if resuming:
            if record.state != TransactionState.CONSUMED_PREPARED:
                raise SystemExit(
                    f"resume-commission requires an existing ConsumedPrepared record, found {record.state.name} "
                    "-- use commission-existing for a fresh Issued grant, or activate-existing if a prepared "
                    "root already exists"
                )
            if record.root_bound:
                raise SystemExit(
                    "resume-commission requires a root-UNBOUND ConsumedPrepared record -- a root-bound record "
                    "means a prepared root was already staged and ActivationSpent should be (re)attempted via "
                    "activate-existing, never re-prepared from scratch"
                )
        else:
            if record.state != TransactionState.ISSUED:
                raise SystemExit(
                    f"commission-existing requires a freshly-Issued record, found {record.state.name} -- use "
                    "resume-commission to continue an interrupted prepare, or activate-existing if a prepared "
                    "root already exists"
                )
            _verify_still_lineage_tip(pair, grant, transaction_id)
            if not pair.commit_state_transition(
                transaction_id, TransactionState.CONSUMED_PREPARED, bytes(DIGEST_BYTES), False, bytes(CHALLENGE_BYTES)
            ):
                raise SystemExit("commit_state_transition(ConsumedPrepared) failed on at least one registry copy")
            confirmed = pair.confirm_both_copies_durable(transaction_id, TransactionState.CONSUMED_PREPARED)
            if confirmed.outcome != ReconciliationOutcome.AGREED:
                raise SystemExit(
                    "ConsumedPrepared did not durably land on BOTH registry copies after a fresh cold readback "
                    "-- refusing to proceed to device I/O"
                )

        certify_transaction_id = _hex_bytes(args.baseline_transaction_id, TRANSACTION_ID_BYTES,
                                             "--baseline-transaction-id")
        certify_result = pair.reconcile(certify_transaction_id)
        if certify_result.outcome != ReconciliationOutcome.AGREED or certify_result.resolved is None:
            raise SystemExit(
                "refusing to prepare: --baseline-transaction-id is not an AGREED durable record in both registries"
            )
        certify_txn = certify_result.resolved.txn
        if certify_txn.operation != AuthorityOperation.CERTIFY_EXISTING_BASELINE:
            raise SystemExit("--baseline-transaction-id does not refer to a CertifyExistingBaseline transaction")

        manifest = _baseline_manifest_from_args(args)
        if compute_baseline_manifest_digest(manifest) != certify_txn.manifest_digest_sha256:
            raise SystemExit(
                "the supplied baseline manifest field values do not hash to the CertifyExistingBaseline "
                "transaction's recorded manifest digest -- refusing to prepare with mismatched evidence"
            )

        # Real production transport: an ota_rf_lab.FramedSerial instance
        # against an explicit operator-supplied /dev/serial/by-id/... path
        # (FramedSerial's own constructor refuses anything else). Tests
        # inject an explicit in-process fake responder instead -- never
        # real hardware is driven by this module's own test suite.
        transport = (transport_factory or (lambda p: _default_transport_factory(p, Path(args.work_dir))))(
            args.serial_path
        )
        session = MaintenanceSessionClient(transport)

        host_challenge = secrets.token_bytes(CHALLENGE_BYTES)
        measurement = read_device_measurement(session, host_challenge)
        verify_measurement_matches_binding(measurement, grant.binding)
        # Sol HIGH2 fix: also verify the device's measured image/SDK/
        # loader/config evidence against the certified baseline (C/B),
        # BEFORE any device mutation (grant upload, PREPARE trigger) or
        # registry spend -- never merely UID/PK/profile/layout.
        verify_measurement_matches_certified_baseline(measurement, manifest, certify_txn.binding)

        session.upload_object(maint.ObjectKind.AUTHORITY_GRANT, serialize_record(grant))

        # Per MAIN's adapter clarification: PREPARE needs the retained raw
        # 626-byte PREPARE_INPUT material itself, not merely its digest
        # folded into the 267-byte PrepareAuthorizationV1 -- one kind per
        # ticket, uploaded into its own typed immutable job-input slot via
        # ordinary sequential PUT_FRAGMENT, strictly BEFORE triggering
        # PREPARE (same session/ticket, no compound wire object, no
        # restart). The device independently verifies input_digest_sha256
        # against this retained buffer rather than trusting an opaque
        # digest alone.
        prepare_input_bytes = build_prepare_authorization_input_bytes(
            grant, certify_txn, manifest, PrepareRxContextKind.NONE, bytes(PUBLIC_KEY_BYTES)
        )
        session.upload_object(maint.ObjectKind.PREPARE_INPUT, prepare_input_bytes)

        # Only AFTER the prepare inputs are fully frozen (both retained
        # objects uploaded) do we mint the single authoritative,
        # purpose-bound device challenge for THIS PREPARE job -- never
        # MEASUREMENT.device_nonce (a real production call-path mismatch
        # identified and corrected per MAIN's adapter directive: that was
        # an unqualified-entropy substitution, not this job's own fresh
        # device-session continuation).
        device_challenge = session.obtain_device_challenge(int(maint.Subcommand.PREPARE))

        prepare = PrepareAuthorizationV1(
            transaction_id=transaction_id,
            grant_digest_sha256=compute_record_digest_sha256(grant),
            input_digest_sha256=hashlib.sha256(prepare_input_bytes).digest(),
            authorized_revision=grant.revision,
            expected_binding=grant.binding,
            device_fresh_challenge=device_challenge,
            host_nonce=host_challenge,
        )
        prepare_signed_message = serialize_prepare_authorization_signed_message(prepare)
        prepare.issuer_signature_ed25519 = sign_bytes(
            prepare_signed_message, Path(args.issuer_private_key), Path(args.work_dir)
        )

        session.upload_object(maint.ObjectKind.PREPARE_AUTHORIZATION, serialize_prepare_authorization_record(prepare))
        trigger_reply = session.trigger(maint.Subcommand.PREPARE)
        if trigger_reply.status not in (maint.Status.OK, maint.Status.PENDING):
            raise MaintenanceProtocolError(
                f"PREPARE denied by device: status={trigger_reply.status!r} reason={trigger_reply.reason!r}"
            )
        if trigger_reply.status == maint.Status.PENDING:
            session.require_ok(session.poll_until_terminal(), "PREPARE (poll)")

        prepare_ack_record = session.download_object(maint.ObjectKind.PREPARE_ACK)
        ack = parse_prepared_root_response(prepare_ack_record)
        # Authenticity comes ENTIRELY from verifying the device's real
        # Ed25519 signature over the canonical AuthorityAckCodec message.
        # Per MAIN's Sol-freeze correction: the message's legacy-named
        # first argument ("hostChallenge" in the shared C++ codec) MUST
        # carry the exact DEVICE-minted authorization challenge C
        # returned by obtain_device_challenge() for THIS PREPARE job --
        # never OPEN's host_challenge (session/measurement correlation
        # only). Using host_challenge here was a confirmed production
        # call-path mismatch; ack.device_nonce is used exactly as the
        # device itself reported and signed it, with no separate
        # equality-proxy assertion against it.
        ack_message = serialize_prepare_ack_message(
            device_challenge, ack.device_nonce, transaction_id, ack.root_digest_sha256
        )
        if not verify_bytes(
            ack_message, ack.device_signature_ed25519, grant.binding.mesh_full_public_key, Path(args.work_dir)
        ):
            raise SystemExit("device PREPARE_ACK signature verification failed -- refusing to treat as prepared")

        prepared_artifact = session.download_object(maint.ObjectKind.PREPARED_ARTIFACT)
        if compute_prepared_root_commitment_sha256(prepared_artifact) != ack.root_digest_sha256:
            raise SystemExit(
                "PREPARED_ARTIFACT commitment digest does not match the device's own signed PREPARE_ACK root "
                "digest -- refusing (the manifest/artifact must never be trusted ahead of the device's own "
                "signed claim about what it actually staged)"
            )
        # Sol HIGH3 fix: a signed R alone only proves the device signed
        # an ack about SOME 683-byte buffer -- it proves nothing about
        # that buffer's actual semantic provenance. Fully parse the
        # canonical P683 layout and cross-validate every field against
        # the EXACT authorized grant/certify/manifest/rx-context/peer-key
        # inputs this handshake itself produced, BEFORE any sidecar
        # write or ActivationSpent commit.
        try:
            parsed_artifact = parse_prepared_artifact(prepared_artifact)
        except PreparedArtifactCodecError as exc:
            raise SystemExit(f"PREPARED_ARTIFACT is malformed -- refusing: {exc}") from exc
        verify_prepared_artifact_semantics(
            parsed_artifact, grant, certify_txn, manifest, PrepareRxContextKind.NONE, bytes(PUBLIC_KEY_BYTES),
            measurement,
        )

        # Sol MEDIUM4 fix: reconcile (never blindly re-write) each
        # copy's provenance sidecar -- a prior attempt may have already
        # durably written ONE copy before being interrupted -- then do a
        # FRESH cold readback of BOTH before ever committing
        # ActivationSpent.
        ensure_prepared_artifact_provenance(registry_a, transaction_id, prepared_artifact, prepare_ack_record)
        ensure_prepared_artifact_provenance(registry_b, transaction_id, prepared_artifact, prepare_ack_record)
        readback_a = read_prepared_artifact_provenance(registry_a, transaction_id)
        readback_b = read_prepared_artifact_provenance(registry_b, transaction_id)
        expected_sidecar = (prepared_artifact, prepare_ack_record)
        if readback_a != expected_sidecar or readback_b != expected_sidecar:
            raise SystemExit(
                "prepared-artifact provenance sidecar readback mismatch on at least one registry copy after a "
                "fresh cold reopen -- refusing to proceed to ActivationSpent"
            )

        _verify_still_lineage_tip(pair, grant, transaction_id)
        if not pair.commit_state_transition(
            transaction_id, TransactionState.ACTIVATION_SPENT, ack.root_digest_sha256, True, device_challenge
        ):
            raise SystemExit("commit_state_transition(ActivationSpent) failed on at least one registry copy")
        final = pair.confirm_both_copies_durable(transaction_id, TransactionState.ACTIVATION_SPENT)
        if final.outcome != ReconciliationOutcome.AGREED:
            raise SystemExit(
                "ActivationSpent did not durably land on BOTH registry copies after a fresh cold readback -- "
                "registries must be repaired before activation permission can ever be considered granted"
            )

        session.close()

        print(f"transaction-id:      {transaction_id.hex()}")
        print("state:               ActivationSpent (root-bound, durably confirmed on BOTH registry copies)")
        print(f"root-digest-sha256:  {ack.root_digest_sha256.hex()}")
        print(
            "NOTE: this grants PREPARE permission only (per Astra section 5/6). Use the separate "
            "'activate-existing' command to drive the actual on-device ACTIVATE exchange against this "
            "EXISTING, already-durable root -- that step consumes NO further registry write."
        )
        return 0
    finally:
        registry_lock.__exit__(None, None, None)


def _run_activate_handshake(
    args: argparse.Namespace,
    transport_factory: Optional[Callable[[str], object]] = None,
) -> int:
    """Delivers the ALREADY-recorded ActivationSpent permit to a real
    device and verifies its signed ACTIVATE_ACK -- mirrors
    AuthorityCoordinator::activateExistingRoot exactly: NO registry
    write happens anywhere in this function (the spend already durably
    happened inside commission-existing/resume-commission); this call
    only ever re-delivers an EXISTING grant/root and is safe to retry
    indefinitely. Device may activate only the EXISTING matching
    prepared root -- it can never reseed an absent/erased store, which
    is why the durable provenance sidecar is re-read and digest-checked
    against the registry's own recorded root BEFORE any device I/O."""
    registry_a = Path(args.registry_a)
    registry_b = Path(args.registry_b)
    transaction_id = _hex_bytes(args.transaction_id, TRANSACTION_ID_BYTES, "--transaction-id")

    registry_lock = CrossProcessRegistryPairLock(registry_a, registry_b)
    registry_lock.__enter__()
    try:
        pair = AuthorityRegistryPair(AuthorityRegistryCopy(registry_a), AuthorityRegistryCopy(registry_b))

        result = pair.reconcile(transaction_id)
        if result.outcome != ReconciliationOutcome.AGREED or result.resolved is None:
            raise SystemExit(
                f"refusing to activate: registries are not in an AGREED state for --transaction-id "
                f"(outcome={result.outcome.name}) -- corrupt/disagreeing/missing history is never resumable"
            )
        record = result.resolved
        grant = record.txn

        if record.state != TransactionState.ACTIVATION_SPENT or not record.root_bound:
            raise SystemExit(
                f"activate-existing requires an existing root-BOUND ActivationSpent record, found "
                f"state={record.state.name} root_bound={record.root_bound} -- use commission-existing/"
                "resume-commission to reach ActivationSpent first; this command never spends a new "
                "registry permission, it only re-delivers an EXISTING one."
            )

        # Zero additional registry spend: re-confirm the ALREADY-recorded
        # ActivationSpent is durable on BOTH copies via a fresh cold
        # readback -- never trust the single reconcile() snapshot above
        # alone (mirrors the C++ coordinator's confirmBothCopiesDurable
        # discipline immediately before any permission is re-delivered).
        confirmed = pair.confirm_both_copies_durable(transaction_id, TransactionState.ACTIVATION_SPENT)
        if confirmed.outcome != ReconciliationOutcome.AGREED or confirmed.resolved is None:
            raise SystemExit(
                "ActivationSpent is not durably confirmed on BOTH registry copies after a fresh cold "
                "readback -- refusing to re-deliver activation until the registries are repaired"
            )
        record = confirmed.resolved

        # Reread the durable prepared-artifact provenance sidecar from
        # BOTH copies (never only one) and confirm its own commitment
        # digest genuinely matches the registry's recorded root. The
        # device's signed ACTIVATE_ACK below proves fresh device-side
        # possession of this EXACT root; this reread is what proves the
        # HOST itself still holds the real artifact that root digest
        # actually commits to -- never a reseed/placeholder/guessed root.
        artifact_a, _ = read_prepared_artifact_provenance(registry_a, transaction_id)
        artifact_b, _ = read_prepared_artifact_provenance(registry_b, transaction_id)
        if artifact_a != artifact_b:
            raise SystemExit(
                "prepared-artifact provenance sidecars on the two registry copies do not match -- refusing "
                "to activate against disagreeing evidence"
            )
        if compute_prepared_root_commitment_sha256(artifact_a) != record.prepared_root_digest_sha256:
            raise SystemExit(
                "prepared-artifact provenance sidecar commitment digest does not match the registry's "
                "recorded ActivationSpent root digest -- refusing to activate against mismatched evidence"
            )

        transport = (transport_factory or (lambda p: _default_transport_factory(p, Path(args.work_dir))))(
            args.serial_path
        )
        session = MaintenanceSessionClient(transport)

        host_challenge = secrets.token_bytes(CHALLENGE_BYTES)
        measurement = read_device_measurement(session, host_challenge)
        verify_measurement_matches_binding(measurement, grant.binding)

        # Only AFTER verifying this is genuinely the same physical device
        # do we mint the single authoritative, purpose-bound device
        # challenge for THIS ACTIVATE job -- independent of MEASUREMENT's
        # own device_nonce and OPEN's host_challenge (same discipline as
        # the PREPARE handshake above).
        device_challenge = session.obtain_device_challenge(int(maint.Subcommand.ACTIVATE))

        auth = ActivationAuthorizationV1(
            transaction_id=transaction_id,
            grant_digest_sha256=compute_record_digest_sha256(grant),
            # The ACTUAL registry-recorded ActivationSpent root -- read
            # back from `record` above, not any issuer-expected value, so
            # this authorization proves what the durable record genuinely
            # says, not merely what was originally expected.
            prepared_root_digest_sha256=record.prepared_root_digest_sha256,
            spent_authorized_revision=grant.revision,
            expected_binding=grant.binding,
            device_fresh_challenge=device_challenge,
            host_nonce=host_challenge,
        )
        signed_message = serialize_activation_authorization_signed_message(auth)
        auth.issuer_signature_ed25519 = sign_bytes(
            signed_message, Path(args.issuer_private_key), Path(args.work_dir)
        )

        session.upload_object(
            maint.ObjectKind.ACTIVATION_AUTHORIZATION, serialize_activation_authorization_record(auth)
        )
        trigger_reply = session.trigger(maint.Subcommand.ACTIVATE)
        if trigger_reply.status not in (maint.Status.OK, maint.Status.PENDING):
            raise MaintenanceProtocolError(
                f"ACTIVATE denied by device: status={trigger_reply.status!r} reason={trigger_reply.reason!r}"
            )
        if trigger_reply.status == maint.Status.PENDING:
            session.require_ok(session.poll_until_terminal(), "ACTIVATE (poll)")

        activate_ack_record = session.download_object(maint.ObjectKind.ACTIVATE_ACK)
        ack = parse_activation_response(activate_ack_record)
        # Authenticity comes ENTIRELY from verifying the device's real
        # Ed25519 signature over the canonical AuthorityAckCodec message,
        # domain-separated from a prepare-ack (ACK_TAG_ACTIVATE) so a
        # signed prepare acknowledgement can never be replayed here. The
        # message's legacy-named first argument carries the exact
        # DEVICE-minted authorization challenge C just obtained above --
        # never OPEN's host_challenge.
        ack_message = serialize_activate_ack_message(
            device_challenge, ack.device_nonce, transaction_id, record.prepared_root_digest_sha256
        )
        if not verify_bytes(
            ack_message, ack.device_signature_ed25519, grant.binding.mesh_full_public_key, Path(args.work_dir)
        ):
            raise SystemExit("device ACTIVATE_ACK signature verification failed -- refusing to treat as activated")

        session.close()

        print(f"transaction-id:      {transaction_id.hex()}")
        print("state:               ActivationSpent (re-delivered to device; NO additional registry write "
              "performed)")
        print(f"root-digest-sha256:  {record.prepared_root_digest_sha256.hex()}")
        return 0
    finally:
        registry_lock.__exit__(None, None, None)


def _cmd_commission_existing(args: argparse.Namespace) -> int:
    return _run_prepare_handshake(args, resuming=False)


def _cmd_resume_commission(args: argparse.Namespace) -> int:
    return _run_prepare_handshake(args, resuming=True)


def _cmd_activate_existing(args: argparse.Namespace) -> int:
    return _run_activate_handshake(args)


def _cmd_inspect_commission(args: argparse.Namespace) -> int:
    """Pure local registry reconciliation + print -- explicitly NO
    device I/O (the lowest-risk operation in this module)."""
    pair = AuthorityRegistryPair(AuthorityRegistryCopy(Path(args.registry_a)), AuthorityRegistryCopy(Path(args.registry_b)))
    transaction_id = _hex_bytes(args.transaction_id, TRANSACTION_ID_BYTES, "--transaction-id")
    result = pair.reconcile(transaction_id)
    print(f"outcome: {result.outcome.name}")
    if result.resolved is not None:
        txn = result.resolved.txn
        binding = txn.binding
        print(f"state:                        {result.resolved.state.name}")
        print(f"root_bound:                   {result.resolved.root_bound}")
        print(f"prepared_root_digest_sha256:  {result.resolved.prepared_root_digest_sha256.hex()}")
        print(f"operation:                    {txn.operation.name}")
        print(f"revision:                     {txn.revision}")
        print(f"predecessor_transaction_id:   {txn.predecessor_transaction_id.hex()}")
        print(f"hardware_uid:                 {binding.hardware_uid.hex()}")
        print(f"mesh_full_public_key:         {binding.mesh_full_public_key.hex()}")
        print(f"crypto_form:                  {binding.crypto_form.name}")
        print(f"group_selector:               {binding.group_selector}")
        print(f"profile_id:                   {binding.profile_id}")
        print(f"layout_id:                    {binding.layout_id}")
        print(f"needs_replica_repair:         {result.needs_replica_repair}")
        try:
            artifact, prepare_ack_record = read_prepared_artifact_provenance(Path(args.registry_a), transaction_id)
            print(f"provenance sidecar (registry-a): present, {len(artifact)}B artifact + {len(prepare_ack_record)}B ack")
        except (FileNotFoundError, ProvenanceSidecarError) as exc:
            print(f"provenance sidecar (registry-a): absent/unreadable ({exc})")
    return 0 if result.outcome != ReconciliationOutcome.UNCERTAIN else 1


def _cmd_issue(args: argparse.Namespace) -> int:
    binding = AuthorityBinding(
        hardware_uid=_hex_bytes(args.hardware_uid, HARDWARE_UID_BYTES, "--hardware-uid"),
        mesh_full_public_key=_hex_bytes(args.mesh_public_key, PUBLIC_KEY_BYTES, "--mesh-public-key"),
        crypto_form=CryptoDomainForm.GROUP if args.crypto_form == "group" else CryptoDomainForm.PAIRWISE,
        group_selector=args.group_selector,
        profile_id=args.profile_id,
        layout_id=args.layout_id,
        historical_initial_role_id=args.initial_role_id,
        consent_owner_public_key=_hex_bytes(args.consent_owner_key, PUBLIC_KEY_BYTES, "--consent-owner-key"),
    )
    if binding.crypto_form == CryptoDomainForm.PAIRWISE and binding.group_selector != 0:
        raise SystemExit("--group-selector must be 0 for a pairwise crypto domain")

    transaction_id = _hex_bytes(args.transaction_id, TRANSACTION_ID_BYTES, "--transaction-id") \
        if args.transaction_id else secrets.token_bytes(TRANSACTION_ID_BYTES)
    predecessor = (
        _hex_bytes(args.predecessor_id, TRANSACTION_ID_BYTES, "--predecessor-id")
        if args.predecessor_id
        else bytes(TRANSACTION_ID_BYTES)
    )
    operation = AuthorityOperation[args.operation.upper().replace("-", "_")]
    if operation not in (AuthorityOperation.COMMISSION, AuthorityOperation.CERTIFY_EXISTING_BASELINE) and args.revision == 0:
        raise SystemExit("--revision must be > 0 for repair/rekey (0 is reserved for first Commission)")
    if operation == AuthorityOperation.COMMISSION and args.revision != 0:
        raise SystemExit("--revision must be 0 for a first Commission")
    if operation == AuthorityOperation.CERTIFY_EXISTING_BASELINE:
        # Mirrors AuthorityCoordinator::submitCertifyExistingBaseline's
        # defense-in-depth guards: this operation never chains off prior
        # history and never seeds a counter -- it is not part of the
        # Commission/Repair/Rekey lineage at all.
        if args.revision != 0:
            raise SystemExit("--revision must be 0 for certify-existing-baseline (it has no lineage to chain from)")
        if predecessor != bytes(TRANSACTION_ID_BYTES):
            raise SystemExit("--predecessor-id must be omitted/zero for certify-existing-baseline")
        if args.tx_floor != 0 or args.rx_floor != 0:
            raise SystemExit("--tx-floor/--rx-floor must both be 0 for certify-existing-baseline (it seeds no counters)")

    registry_lock = CrossProcessRegistryPairLock(Path(args.registry_a), Path(args.registry_b))
    registry_lock.__enter__()
    try:
        pair = AuthorityRegistryPair(
            AuthorityRegistryCopy(Path(args.registry_a)), AuthorityRegistryCopy(Path(args.registry_b))
        )

        txn = AuthorityTransaction(
            binding=binding,
            operation=operation,
            transaction_id=transaction_id,
            revision=args.revision,
            predecessor_transaction_id=predecessor,
            manifest_digest_sha256=_hex_bytes(args.manifest_digest, DIGEST_BYTES, "--manifest-digest"),
            initial_tx_sequence_floor=args.tx_floor,
            initial_rx_replay_floor=args.rx_floor,
            issuer_key_id=args.issuer_key_id,
            issued_at_unix_seconds=args.issued_at,
        )

        # HIGH6: never sign a Commission/Repair/Rekey transaction blind --
        # reconcile the SAME exact ownership identity's surviving history
        # from BOTH registry copies first. This mirrors
        # AuthorityCoordinator::submitCommission/repairExisting/rekeyExplicitly
        # exactly: an operator-supplied --revision/--predecessor-id is never
        # trusted on its own, and missing/uncertain history is never treated
        # as first-use proof.
        if operation == AuthorityOperation.COMMISSION:
            prior = pair.reconcile_latest_activation_for_owner(binding)
            if prior.outcome in (
                ReconciliationOutcome.AGREED,
                ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY,
            ):
                raise SystemExit(
                    "refusing to issue a fresh Commission: this exact ownership "
                    "(hardware-uid+mesh-public-key+crypto-domain+layout) already "
                    "has surviving ActivationSpent history -- a role/label change "
                    "alone is never a fresh Commission; use --operation rekey for "
                    "a genuine key-material change, or repair for counter recovery"
                )
            if prior.outcome == ReconciliationOutcome.UNCERTAIN:
                raise SystemExit(
                    "refusing to issue a fresh Commission: registry copies disagree "
                    "about this ownership's history -- reconcile/repair the "
                    "registries before commissioning, corrupt/conflicting history "
                    "is never first-use proof"
                )
            # H3 fix: the check above is structurally blind to a sibling
            # revision-0 Commission for this SAME owner that has reached
            # Issued or ConsumedPrepared but not yet ActivationSpent -- two
            # distinct genesis transactions could otherwise both be issued
            # and race towards ActivationSpent (a genuine ownership fork).
            # reconcile_ownership_lineage scans ANY state, closing that gap.
            lineage = pair.reconcile_ownership_lineage(binding)
            if lineage.outcome in (
                ReconciliationOutcome.AGREED,
                ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY,
            ):
                raise SystemExit(
                    "refusing to issue a fresh Commission: this exact ownership "
                    "already has a surviving Issued/ConsumedPrepared/ActivationSpent "
                    "record -- a second genesis Commission is never permitted while "
                    "any prior record for this owner exists, spent or not"
                )
            if lineage.outcome == ReconciliationOutcome.UNCERTAIN:
                raise SystemExit(
                    "refusing to issue a fresh Commission: registry copies disagree "
                    "about this ownership's lineage -- reconcile/repair the "
                    "registries before commissioning, corrupt/conflicting history "
                    "is never first-use proof"
                )
            # Sol43 HIGH fix: the two checks above are both scoped to
            # same_ownership (hardware_uid+mesh_full_public_key+
            # crypto_form+group_selector+layout_id), so despite their
            # stated intent, they do NOT actually catch a relabeled
            # crypto-domain/layout/profile (or a changed mesh public key)
            # for the SAME physical chip -- that is a genuinely different
            # "owner" by those checks' definition, so a fresh genesis
            # Commission claiming a different crypto-domain/layout label
            # (or key) was previously accepted even though real history
            # already exists for this exact physical device. The lifetime
            # fork-fence (same_physical_lifetime: hardware_uid ONLY,
            # independent of fullPK/profile/layout/role/crypto-domain
            # labels) must ALSO be checked here, not just for Rekey, so NO
            # relabel of any kind -- including a different AEAD crypto-form
            # /group-selector -- can smuggle a fresh "genesis" Commission
            # in over an already-commissioned physical device.
            physical_lineage = pair.reconcile_physical_lineage(binding)
            if physical_lineage.outcome == ReconciliationOutcome.UNCERTAIN:
                raise SystemExit(
                    "refusing to issue a fresh Commission: registry copies disagree "
                    "about this physical device's surviving lineage -- reconcile/"
                    "repair the registries before commissioning, corrupt/conflicting "
                    "history is never first-use proof"
                )
            if physical_lineage.outcome in (
                ReconciliationOutcome.AGREED,
                ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY,
            ):
                raise SystemExit(
                    "refusing to issue a fresh Commission: this exact PHYSICAL "
                    "hardware-uid already has a surviving Issued/ConsumedPrepared/"
                    "ActivationSpent record under a different mesh-public-key, "
                    "crypto-domain, profile, or layout -- a relabel of any kind is "
                    "never a fresh genesis Commission; use --operation rekey/repair "
                    "to extend this physical device's real history instead"
                )
        elif operation == AuthorityOperation.REPAIR:
            prior = pair.reconcile_latest_activation_for_owner(binding)
            if prior.outcome not in (
                ReconciliationOutcome.AGREED,
                ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY,
            ):
                raise SystemExit(
                    "refusing to issue a Repair: no surviving ActivationSpent "
                    "history found (or registries disagree) for this exact "
                    "ownership -- missing history is never repairable, it "
                    "requires a genuine Commission/rekey/recovery instead"
                )
            assert prior.resolved is not None
            if not _chains_from_predecessor(txn, prior.resolved.txn):
                raise SystemExit(
                    "refusing to issue a Repair: --revision/--predecessor-id do not "
                    "chain from the exact surviving activated transaction "
                    f"(expected revision {prior.resolved.txn.revision + 1} chaining "
                    f"from predecessor-id {prior.resolved.txn.transaction_id_hex()})"
                )
            if txn.initial_tx_sequence_floor < prior.resolved.txn.initial_tx_sequence_floor:
                raise SystemExit("refusing to issue a Repair: --tx-floor would lower the surviving TX floor")
            if txn.initial_rx_replay_floor < prior.resolved.txn.initial_rx_replay_floor:
                raise SystemExit("refusing to issue a Repair: --rx-floor would lower the surviving RX floor")
            # Sol HIGH1 fix: `prior` above is scoped to
            # reconcile_latest_activation_for_owner(binding) -- the EXACT
            # ownership identity (including mesh_full_public_key) this
            # Repair claims to extend. That alone is structurally blind to
            # a DIFFERENT, more recent transaction already in flight for
            # the SAME PHYSICAL hardware-uid under a DIFFERENT key/label
            # (e.g. a Rekey old-key->new-key that has reached Issued or
            # ConsumedPrepared but not yet ActivationSpent): without this
            # check, a Repair chaining from the OLD owner's last
            # ActivationSpent would still validate "chains from predecessor"
            # against stale history, letting two divergent lineages
            # (the in-flight Rekey, and this Repair) both claim the same
            # predecessor/revision -- a genuine ownership fork. Require the
            # PHYSICAL tip (reconcile_physical_lineage, fullPK-independent,
            # highest-revision-wins across ANY state) to be EXACTLY the
            # Repair's own predecessor, or EXACTLY this same candidate
            # transaction_id already recorded (a legitimate retry of an
            # already-issued Repair, not a fork) -- any other physical tip
            # denies outright before any signing/Issued commit.
            physical_lineage = pair.reconcile_physical_lineage(binding)
            if physical_lineage.outcome == ReconciliationOutcome.UNCERTAIN:
                raise SystemExit(
                    "refusing to issue a Repair: registry copies disagree about "
                    "this physical device's surviving lineage -- reconcile/repair "
                    "the registries before repairing, corrupt/conflicting history "
                    "is never repairable"
                )
            if physical_lineage.outcome in (
                ReconciliationOutcome.AGREED,
                ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY,
            ):
                assert physical_lineage.resolved is not None
                physical_tip_id = physical_lineage.resolved.txn.transaction_id
                if physical_tip_id not in (txn.predecessor_transaction_id, txn.transaction_id):
                    raise SystemExit(
                        "refusing to issue a Repair: this physical hardware-uid's "
                        "real tip transaction is NOT this Repair's declared "
                        "predecessor -- a different transaction (e.g. a pending "
                        "Rekey to a different mesh-public-key that has not yet "
                        "reached ActivationSpent) already supersedes the owner "
                        "history this Repair was computed against; a Repair must "
                        "chain from the ACTUAL physical tip, never a stale owner-"
                        "scoped predecessor, to avoid forking the same "
                        "predecessor/revision across two divergent lineages"
                    )
        elif operation == AuthorityOperation.REKEY:
            if not args.prior_mesh_public_key:
                raise SystemExit("--prior-mesh-public-key is required for rekey (the owner lookup must use the OLD key)")
            prior_mesh_public_key = _hex_bytes(
                args.prior_mesh_public_key, PUBLIC_KEY_BYTES, "--prior-mesh-public-key"
            )
            if prior_mesh_public_key == binding.mesh_full_public_key:
                raise SystemExit(
                    "refusing to issue a Rekey: --mesh-public-key is identical to "
                    "--prior-mesh-public-key -- a label/role change alone is never "
                    "a genuine rekey, real key material must change"
                )
            prior_binding = AuthorityBinding(
                hardware_uid=binding.hardware_uid,
                mesh_full_public_key=prior_mesh_public_key,
                crypto_form=binding.crypto_form,
                group_selector=binding.group_selector,
                profile_id=binding.profile_id,
                layout_id=binding.layout_id,
                historical_initial_role_id=binding.historical_initial_role_id,
                consent_owner_public_key=binding.consent_owner_public_key,
            )
            prior = pair.reconcile_latest_activation_for_owner(prior_binding)
            if prior.outcome not in (
                ReconciliationOutcome.AGREED,
                ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY,
            ):
                raise SystemExit(
                    "refusing to issue a Rekey: no surviving ActivationSpent "
                    "history found (or registries disagree) for --prior-mesh-public-key "
                    "under this hardware-uid+crypto-domain+layout -- missing history "
                    "is never a rekey target"
                )
            assert prior.resolved is not None
            if not _chains_from_predecessor(txn, prior.resolved.txn):
                raise SystemExit(
                    "refusing to issue a Rekey: --revision/--predecessor-id do not "
                    "chain from the exact surviving activated transaction "
                    f"(expected revision {prior.resolved.txn.revision + 1} chaining "
                    f"from predecessor-id {prior.resolved.txn.transaction_id_hex()})"
                )

            # H-finding fix ("rekey A->B reaches Issued/ConsumedPrepared but
            # not yet ActivationSpent, then a competing rekey A->C for the
            # SAME predecessor+revision is ALSO accepted"): `prior` above is
            # scoped to reconcile_latest_activation_for_owner, which ONLY
            # ever sees the OLD key's ActivationSpent record -- it is
            # structurally blind to a PENDING (not yet activated) successor
            # already claimed under a DIFFERENT new fullPK, because that
            # successor's Issued/ConsumedPrepared rows are filed under ITS
            # OWN fullPK, not the old one. reconcile_physical_lineage scans
            # by physical device identity (hardware_uid ONLY, deliberately
            # ignoring fullPK, crypto-domain, AND layout -- Sol43 HIGH fix)
            # across ANY state, so it sees exactly that pending successor. If the lineage tip is
            # neither the OLD key's own record (no successor pending yet)
            # nor THIS candidate itself, some OTHER transaction already
            # claimed this predecessor+revision -- block the fork here
            # rather than silently letting both succeed.
            lineage = pair.reconcile_physical_lineage(prior_binding)
            if lineage.outcome == ReconciliationOutcome.UNCERTAIN:
                raise SystemExit(
                    "refusing to issue a Rekey: registry copies disagree about "
                    "this physical device's surviving lineage -- reconcile/repair "
                    "the registries before rekeying"
                )
            if lineage.outcome in (
                ReconciliationOutcome.AGREED,
                ReconciliationOutcome.RECOVERED_FROM_SINGLE_COPY,
            ):
                tip_is_prior = lineage.resolved.txn.transaction_id == prior.resolved.txn.transaction_id
                tip_is_this_candidate = lineage.resolved.txn.transaction_id == txn.transaction_id
                if not tip_is_prior and not tip_is_this_candidate:
                    raise SystemExit(
                        "refusing to issue a Rekey: a DIFFERENT transaction "
                        f"(id {lineage.resolved.txn.transaction_id_hex()}, revision "
                        f"{lineage.resolved.txn.revision}) already claims this exact "
                        "predecessor+revision for this physical device -- a fork is "
                        "never permitted, even before the competing successor "
                        "activates"
                    )

        message = serialize_signed_message(txn)
        txn.issuer_signature_ed25519 = sign_bytes(message, Path(args.issuer_private_key), Path(args.work_dir))

        if not pair.commit_issued(txn):
            raise SystemExit(
                "commitIssued failed on at least one registry copy -- inspect both copies before retrying; "
                "the transaction id may already exist, or a copy is unwritable"
            )
        print(f"transaction-id: {txn.transaction_id_hex()}")
        print(f"operation:      {operation.name}")
        print(f"revision:       {txn.revision}")
    finally:
        registry_lock.__exit__(None, None, None)
    return 0


def _cmd_compute_baseline_manifest_digest(args: argparse.Namespace) -> int:
    """Prints the hex SHA-256 digest of a CertifyExistingBaseline evidence
    manifest, for use as `issue --operation certify-existing-baseline
    --manifest-digest <this output>`. Performs no I/O beyond stdout --
    the actual image/loader hashing (obtaining these hex arguments in the
    first place) is explicitly the operator's/Firmware's job, not this
    CLI's; this only computes the canonical digest of already-known
    evidence hashes/values."""
    manifest = BaselineCertificationManifest(
        approved_image_sha256=_hex_bytes(args.approved_image_sha256, BASELINE_IMAGE_DIGEST_BYTES,
                                          "--approved-image-sha256"),
        approved_image_extent_offset=args.approved_image_extent_offset,
        approved_image_extent_length=args.approved_image_extent_length,
        expected_sdk28_sha256_digest=_hex_bytes(args.expected_sdk28_sha256_digest, BASELINE_SDK_DIGEST_BYTES,
                                                 "--expected-sdk28-sha256-digest"),
        stock_loader_artifact_sha256=_hex_bytes(args.stock_loader_artifact_sha256,
                                                 BASELINE_STOCK_LOADER_DIGEST_BYTES,
                                                 "--stock-loader-artifact-sha256"),
        stock_loader_artifact_range_start=args.stock_loader_artifact_range_start,
        stock_loader_artifact_range_length=args.stock_loader_artifact_range_length,
        boot_config_id=args.boot_config_id,
        allow_ordinary_userdata=args.allow_ordinary_userdata,
    )
    digest = compute_baseline_manifest_digest(manifest)
    print(digest.hex())
    return 0


def _cmd_reconcile(args: argparse.Namespace) -> int:
    pair = AuthorityRegistryPair(
        AuthorityRegistryCopy(Path(args.registry_a)), AuthorityRegistryCopy(Path(args.registry_b))
    )
    transaction_id = _hex_bytes(args.transaction_id, TRANSACTION_ID_BYTES, "--transaction-id")
    result = pair.reconcile(transaction_id)
    print(f"outcome: {result.outcome.name}")
    if result.resolved is not None:
        print(f"state:   {result.resolved.state.name}")
        print(f"needs_replica_repair: {result.needs_replica_repair}")
    return 0 if result.outcome != ReconciliationOutcome.UNCERTAIN else 1


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate-issuer-key", help="Generate a new offline issuer Ed25519 keypair.")
    gen.add_argument("--key-dir", required=True, help="Explicit directory to hold the new keypair (never a default).")
    gen.add_argument("--name", default="issuer")
    gen.set_defaults(func=_cmd_generate_issuer_key)

    issue = sub.add_parser("issue", help="Sign and commit a new Commission/Repair/Rekey transaction.")
    issue.add_argument("--registry-a", required=True)
    issue.add_argument("--registry-b", required=True)
    issue.add_argument("--issuer-private-key", required=True)
    issue.add_argument("--work-dir", required=True, help="Scratch directory for signing (never /tmp).")
    issue.add_argument("--operation", required=True,
                        choices=("commission", "repair", "rekey", "certify-existing-baseline"))
    issue.add_argument("--hardware-uid", required=True)
    issue.add_argument("--mesh-public-key", required=True)
    issue.add_argument("--crypto-form", choices=("pairwise", "group"), default="pairwise")
    issue.add_argument("--group-selector", type=int, default=0)
    issue.add_argument("--profile-id", type=lambda x: int(x, 0), required=True)
    issue.add_argument("--layout-id", type=lambda x: int(x, 0), required=True)
    issue.add_argument("--initial-role-id", type=lambda x: int(x, 0), default=0)
    issue.add_argument("--consent-owner-key", required=True)
    issue.add_argument("--transaction-id", default=None, help="16-byte hex; random if omitted.")
    issue.add_argument("--predecessor-id", default=None)
    issue.add_argument("--revision", type=int, default=0)
    issue.add_argument("--prior-mesh-public-key", default=None,
                        help="Required for --operation rekey: the OLD mesh public key, used to "
                             "look up the surviving ownership history being rekeyed away from "
                             "(the new --mesh-public-key cannot be used for that lookup).")
    issue.add_argument("--manifest-digest", required=True)
    issue.add_argument("--tx-floor", type=lambda x: int(x, 0), required=True)
    issue.add_argument("--rx-floor", type=lambda x: int(x, 0), required=True)
    issue.add_argument("--issuer-key-id", type=lambda x: int(x, 0), required=True)
    issue.add_argument("--issued-at", type=int, required=True, help="Unix seconds; audit trail only.")
    issue.set_defaults(func=_cmd_issue)

    recon = sub.add_parser("reconcile", help="Report the reconciled state of a transaction id.")
    recon.add_argument("--registry-a", required=True)
    recon.add_argument("--registry-b", required=True)
    recon.add_argument("--transaction-id", required=True)
    recon.set_defaults(func=_cmd_reconcile)

    baseline = sub.add_parser(
        "compute-baseline-manifest-digest",
        help="Compute the manifest digest for a CertifyExistingBaseline transaction's --manifest-digest argument.",
    )
    baseline.add_argument("--approved-image-sha256", required=True)
    baseline.add_argument("--approved-image-extent-offset", type=lambda x: int(x, 0), required=True)
    baseline.add_argument("--approved-image-extent-length", type=lambda x: int(x, 0), required=True)
    baseline.add_argument("--expected-sdk28-sha256-digest", required=True,
                           help="Full SHA-256 hex digest of the exact, frozen SDK identifier bytes "
                                "(NOT a version integer).")
    baseline.add_argument("--stock-loader-artifact-sha256", required=True)
    baseline.add_argument("--stock-loader-artifact-range-start", type=lambda x: int(x, 0), required=True)
    baseline.add_argument("--stock-loader-artifact-range-length", type=lambda x: int(x, 0), required=True)
    baseline.add_argument("--boot-config-id", type=lambda x: int(x, 0), required=True)
    baseline.add_argument("--allow-ordinary-userdata", action="store_true")
    baseline.set_defaults(func=_cmd_compute_baseline_manifest_digest)

    def _add_baseline_manifest_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--baseline-transaction-id", required=True,
                        help="transaction-id of the already-issued CertifyExistingBaseline (C) grant.")
        p.add_argument("--approved-image-sha256", required=True)
        p.add_argument("--approved-image-extent-offset", type=lambda x: int(x, 0), required=True)
        p.add_argument("--approved-image-extent-length", type=lambda x: int(x, 0), required=True)
        p.add_argument("--expected-sdk28-sha256-digest", required=True)
        p.add_argument("--stock-loader-artifact-sha256", required=True)
        p.add_argument("--stock-loader-artifact-range-start", type=lambda x: int(x, 0), required=True)
        p.add_argument("--stock-loader-artifact-range-length", type=lambda x: int(x, 0), required=True)
        p.add_argument("--boot-config-id", type=lambda x: int(x, 0), required=True)
        p.add_argument("--allow-ordinary-userdata", action="store_true")

    commission = sub.add_parser(
        "commission-existing",
        help="Drive a real USB Prepare handshake for a freshly-Issued grant through to a durable "
             "ActivationSpent commit on both registry copies.",
    )
    commission.add_argument("--registry-a", required=True)
    commission.add_argument("--registry-b", required=True)
    commission.add_argument("--transaction-id", required=True)
    commission.add_argument("--issuer-private-key", required=True)
    commission.add_argument("--work-dir", required=True, help="Scratch directory for signing/verifying (never /tmp).")
    commission.add_argument("--serial-path", required=True,
                             help="Explicit /dev/serial/by-id/... device path (never a default/guessed path).")
    _add_baseline_manifest_args(commission)
    commission.set_defaults(func=_cmd_commission_existing)

    resume = sub.add_parser(
        "resume-commission",
        help="Resume an interrupted Prepare handshake for a transaction already durably "
             "ConsumedPrepared (root-unbound) in both registry copies.",
    )
    resume.add_argument("--registry-a", required=True)
    resume.add_argument("--registry-b", required=True)
    resume.add_argument("--transaction-id", required=True)
    resume.add_argument("--issuer-private-key", required=True)
    resume.add_argument("--work-dir", required=True, help="Scratch directory for signing/verifying (never /tmp).")
    resume.add_argument("--serial-path", required=True,
                         help="Explicit /dev/serial/by-id/... device path (never a default/guessed path).")
    _add_baseline_manifest_args(resume)
    resume.set_defaults(func=_cmd_resume_commission)

    activate = sub.add_parser(
        "activate-existing",
        help="Re-deliver an EXISTING durable ActivationSpent permit to the device and verify its signed "
             "ACTIVATE_ACK -- performs NO additional registry write; safe to retry indefinitely.",
    )
    activate.add_argument("--registry-a", required=True)
    activate.add_argument("--registry-b", required=True)
    activate.add_argument("--transaction-id", required=True)
    activate.add_argument("--issuer-private-key", required=True)
    activate.add_argument("--work-dir", required=True, help="Scratch directory for signing/verifying (never /tmp).")
    activate.add_argument("--serial-path", required=True,
                           help="Explicit /dev/serial/by-id/... device path (never a default/guessed path).")
    activate.set_defaults(func=_cmd_activate_existing)

    inspect = sub.add_parser(
        "inspect-commission",
        help="Pure local registry reconciliation + print -- no device I/O.",
    )
    inspect.add_argument("--registry-a", required=True)
    inspect.add_argument("--registry-b", required=True)
    inspect.add_argument("--transaction-id", required=True)
    inspect.set_defaults(func=_cmd_inspect_commission)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
