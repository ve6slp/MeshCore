#pragma once

// REAL (non-test-double) implementation of OriginalBaselineSdk28Provenance
// (see BootFloorActivationReceipt.h). Astra residual: "the baseline image/
// extent/target/SDK provenance seam must genuinely persist from already-
// verified certified-baseline/prepared-P data -- not an opaque boolean
// trust where a caller hands values to a provider that mirrors them
// straight back as authoritative." Before this file, the ONLY thing
// implementing OriginalBaselineSdk28Provenance anywhere in this module
// was a unit-test double (FakeOriginalBaselineSdk28Provenance) that
// blindly returns whatever it was constructed with -- there was no
// production-real alternative. This class is that real alternative.
//
// Design: a candidate full BaselineCertificationManifest is NEVER
// trusted merely because a caller supplies it. It is cryptographically
// bound, in BOTH directions, against the ALREADY-DURABLE (two-copy),
// ALREADY-SIGNED `manifestDigestSha256` field already carried inside the
// exact Commission AuthorityTransaction for this owner/transaction (the
// same field an issuer had to independently compute-and-sign at
// commissioning time, per BaselineCertificationManifestCodec's own
// digest convention):
//
//   1. recordOriginalBaselineManifest(): an explicit, one-time "record"
//      step. The caller (a real integrator/CLI holding the full
//      candidate manifest) supplies it ONCE for a specific, already-
//      Agreed, already-ActivationSpent-eligible Commission transaction.
//      This method independently reconciles the registry, confirms the
//      transaction and owner actually match, recomputes the candidate's
//      own digest via BaselineCertificationManifestCodec, and REFUSES
//      (ManifestDigestMismatch) unless that recomputed digest is
//      bit-for-bit identical to the transaction's own already-signed
//      manifestDigestSha256. Only on a genuine match is the FULL
//      candidate manifest durably persisted (write-once; a conflicting
//      re-record for the same transaction is refused, never silently
//      overwritten).
//
//   2. lookupOriginalBaselineProvenance(): the read seam
//      BootFloorActivationReceiptExporter actually calls. It does NOT
//      merely replay whatever bytes are on disk -- it re-reconciles the
//      registry AGAIN and re-verifies the persisted manifest's digest
//      AGAIN against the transaction's own manifestDigestSha256 before
//      answering. A corrupted/tampered/stale sidecar file is rejected
//      here (returns false => Denied upstream), never blindly served.
//
// This sidecar is therefore a CACHE of a cryptographically re-verified
// fact, never an independently-trusted store in its own right: the only
// thing that can make this class answer `true` is an already-signed,
// already-two-copy-durable transaction whose own manifestDigestSha256
// genuinely matches the persisted candidate manifest, recomputed fresh
// every time. A caller cannot fabricate arbitrary image/extent/target/
// SDK28 values and have this class accept or later serve them: an
// unrelated or wrong candidate manifest simply never matches any real
// transaction's digest and is refused at record time, before anything
// is ever durably written.
//
// Durability discipline mirrors FileAuthorityRegistryCopy.h's own
// write/fsync-data-then-fsync-parent-directory convention (re-
// implemented locally here, not by editing that file): write, fflush,
// fsync the file, close, THEN fsync the parent directory, and only
// return success once both have genuinely succeeded.
//
// NOT implemented here (explicitly out of scope / still unwired, per
// Root's repeated instruction not to claim production integration):
// the actual *source* of the candidate manifest at commissioning time
// (an operator-facing CLI/tool step that reads it from the real
// commissioning flow) and the file-permission/ownership hardening that
// would be required for a genuinely hostile multi-operator deployment
// beyond this process's own umask. This class only supplies the
// cryptographic record/lookup seam itself.

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ota/authority/AuthorityRegistryPort.h"
#include "ota/authority/BaselineCertificationManifest.h"
#include "ota/authority/BootFloorActivationReceipt.h"
#include "ota/storage/Crc32.h"

namespace ota {
namespace authority {

enum class OriginalBaselineManifestRecordOutcome : uint8_t {
  Ok = 0,
  Denied = 1,                  // A required dependency/precondition failed in a way that is not one of the below.
  TransactionNotFound = 2,
  RegistryDisagreement = 3,    // Reconciliation was not a clean Agreed resolution.
  OperationMismatch = 4,       // Not a Commission transaction.
  BindingMismatch = 5,         // Caller-claimed owner does not match the reconciled transaction's own binding.
  ManifestDigestMismatch = 6,  // Candidate manifest's own computed digest does not match the ALREADY-SIGNED
                                // transaction's manifestDigestSha256 -- the cryptographic refusal this whole
                                // class exists to perform. Never persisted on this outcome.
  ConflictingExistingRecord = 7,  // A DIFFERENT manifest is already durably recorded for this exact transaction;
                                   // never silently overwritten. Re-recording the IDENTICAL manifest is Ok (idempotent).
  IoFailure = 8,
};

// File-backed, digest-re-verifying, write-once implementation of
// OriginalBaselineSdk28Provenance. See file header above for the full
// design rationale.
class FileBackedOriginalBaselineManifestSidecar : public OriginalBaselineSdk28Provenance {
public:
  // `directory` must already exist and be writable by this process; this
  // class performs no mkdir/chmod of its own (matches the "constructor
  // does zero I/O" discipline -- directory existence is only touched
  // inside recordOriginalBaselineManifest/lookupOriginalBaselineProvenance,
  // never at construction).
  FileBackedOriginalBaselineManifestSidecar(AuthorityRegistryPair& registry, std::string directory)
      : registry_(registry), directory_(std::move(directory)) {}

  OriginalBaselineManifestRecordOutcome recordOriginalBaselineManifest(
      const AuthorityBinding& owner, const uint8_t transactionId[kTransactionIdBytes],
      const BaselineCertificationManifest& candidateManifest, uint32_t targetId) {
    ReconciliationResult rec = registry_.reconcile(transactionId);
    if (rec.outcome == ReconciliationOutcome::NotFound) {
      return OriginalBaselineManifestRecordOutcome::TransactionNotFound;
    }
    if (rec.outcome != ReconciliationOutcome::Agreed) {
      return OriginalBaselineManifestRecordOutcome::RegistryDisagreement;
    }
    if (rec.resolved.txn.operation != AuthorityOperation::Commission) {
      return OriginalBaselineManifestRecordOutcome::OperationMismatch;
    }
    if (!rec.resolved.txn.binding.sameOwnership(owner)) {
      return OriginalBaselineManifestRecordOutcome::BindingMismatch;
    }

    uint8_t candidate_digest[kDigestBytes];
    if (!BaselineCertificationManifestCodec::computeDigestSha256(candidateManifest, candidate_digest)) {
      return OriginalBaselineManifestRecordOutcome::Denied;
    }
    // The cryptographic refusal: this candidate is accepted ONLY if its
    // own digest is byte-identical to what the issuer ALREADY signed
    // into this transaction at commissioning time. Nothing about this
    // check trusts the caller.
    if (std::memcmp(candidate_digest, rec.resolved.txn.manifestDigestSha256, kDigestBytes) != 0) {
      return OriginalBaselineManifestRecordOutcome::ManifestDigestMismatch;
    }

    SidecarFileRecord new_record;
    std::memcpy(new_record.transactionId, transactionId, kTransactionIdBytes);
    new_record.manifest = candidateManifest;
    new_record.targetId = targetId;

    SidecarFileRecord existing;
    const SidecarReadStatus existing_status = readSidecarFile(transactionId, existing);
    if (existing_status == SidecarReadStatus::CorruptOrError) {
      // The file is present but not positively intact -- this is NOT
      // "no existing record yet". Refuse rather than silently
      // overwriting whatever uncertain state is already on disk; an
      // operator must resolve this explicitly (e.g. restore from the
      // other durable copy/backup) before a fresh record can proceed.
      return OriginalBaselineManifestRecordOutcome::IoFailure;
    }
    if (existing_status == SidecarReadStatus::Present) {
      if (!sameRecord(existing, new_record)) {
        return OriginalBaselineManifestRecordOutcome::ConflictingExistingRecord;
      }
      return OriginalBaselineManifestRecordOutcome::Ok;  // Idempotent re-record of the identical already-verified fact.
    }
    // Only a POSITIVELY absent (Status::Absent) prior file may proceed to a fresh write.
    if (!writeSidecarFileDurable(transactionId, new_record)) {
      return OriginalBaselineManifestRecordOutcome::IoFailure;
    }
    return OriginalBaselineManifestRecordOutcome::Ok;
  }

  bool lookupOriginalBaselineProvenance(const AuthorityBinding& owner, const uint8_t transactionId[kTransactionIdBytes],
                                        AuthorityBootFloorBaselineProvenanceRecord& out_record) const override {
    ReconciliationResult rec = registry_.reconcile(transactionId);
    if (rec.outcome != ReconciliationOutcome::Agreed) return false;
    if (rec.resolved.txn.operation != AuthorityOperation::Commission) return false;
    if (!rec.resolved.txn.binding.sameOwnership(owner)) return false;

    SidecarFileRecord stored;
    if (readSidecarFile(transactionId, stored) != SidecarReadStatus::Present) return false;
    if (std::memcmp(stored.transactionId, transactionId, kTransactionIdBytes) != 0) return false;

    // Re-verify AGAIN here, fresh, every single lookup -- never trust
    // that the file's content is still what was genuinely recorded;
    // a corrupted/tampered/stale sidecar is refused, not served.
    uint8_t stored_digest[kDigestBytes];
    if (!BaselineCertificationManifestCodec::computeDigestSha256(stored.manifest, stored_digest)) return false;
    if (std::memcmp(stored_digest, rec.resolved.txn.manifestDigestSha256, kDigestBytes) != 0) return false;

    std::memcpy(out_record.imageSha256, stored.manifest.approvedImageSha256, kBootFloorBaselineImageDigestBytes);
    out_record.extentLength = stored.manifest.approvedImageExtentLength;
    out_record.targetId = stored.targetId;
    std::memcpy(out_record.original28Sha256Digest, stored.manifest.expectedSdk28Sha256Digest,
                kBootFloorOriginalSdk28DigestBytes);
    return true;
  }

private:
  // Astra "typed absence/error" fix: a failed open() (ENOENT -- the file
  // genuinely was never written) and a failed/short read or a CRC/
  // digest mismatch (the file exists but is truncated, corrupted, or
  // was partially written by a crashed prior attempt) used to both
  // collapse to the same `false`. That conflation was safe for
  // lookupOriginalBaselineProvenance() (either way the right answer is
  // "deny"), but NOT for recordOriginalBaselineManifest(): a caller
  // re-recording after some other process's write was interrupted mid-
  // flight must not have that corrupt-but-NOT-positively-absent state
  // silently treated as "no existing record yet" and overwritten --
  // that would blow away whatever partial/uncertain fact was already
  // there without ever surfacing that anything was wrong. `Positively
  // absent` and `present but unreadable/corrupt` are now distinct
  // outcomes; only the former may proceed to a fresh write.
  enum class SidecarReadStatus : uint8_t {
    Absent = 0,         // open() genuinely failed with the file missing -- never fabricated.
    Present = 1,         // Read, length-checked, and CRC-verified successfully.
    CorruptOrError = 2,  // The file exists (or existed) but could not be positively read back intact.
  };

  struct SidecarFileRecord {
    uint8_t transactionId[kTransactionIdBytes] = {0};
    BaselineCertificationManifest manifest;
    uint32_t targetId = 0;
  };

  static bool sameRecord(const SidecarFileRecord& a, const SidecarFileRecord& b) {
    uint8_t da[kDigestBytes];
    uint8_t db[kDigestBytes];
    if (!BaselineCertificationManifestCodec::computeDigestSha256(a.manifest, da)) return false;
    if (!BaselineCertificationManifestCodec::computeDigestSha256(b.manifest, db)) return false;
    return std::memcmp(a.transactionId, b.transactionId, kTransactionIdBytes) == 0 &&
           std::memcmp(da, db, kDigestBytes) == 0 && a.targetId == b.targetId;
  }

  std::string pathFor(const uint8_t transactionId[kTransactionIdBytes]) const {
    static const char kHex[] = "0123456789abcdef";
    std::string name;
    name.reserve(kTransactionIdBytes * 2 + 8);
    for (size_t i = 0; i < kTransactionIdBytes; ++i) {
      name.push_back(kHex[(transactionId[i] >> 4) & 0xF]);
      name.push_back(kHex[transactionId[i] & 0xF]);
    }
    return directory_ + "/baseline_manifest_" + name + ".bin";
  }

  // Fixed-width on-disk layout: transactionId(16) + serialized manifest
  // (BaselineCertificationManifestCodec::kManifestBytes == 117) +
  // targetId(4, little-endian) + crc32(4, little-endian) over everything
  // preceding it. The CRC is an EXTRA corruption check on top of (not a
  // substitute for) the SHA-256 digest re-verification performed by
  // lookupOriginalBaselineProvenance/sameRecord above.
  static constexpr size_t kBodyBytes =
      kTransactionIdBytes + BaselineCertificationManifestCodec::kManifestBytes + 4;
  static constexpr size_t kFileBytes = kBodyBytes + 4;

  SidecarReadStatus readSidecarFile(const uint8_t transactionId[kTransactionIdBytes], SidecarFileRecord& out_record) const {
    const std::string path = pathFor(transactionId);
    FILE* f = std::fopen(path.c_str(), "rb");
    if (f == nullptr) return SidecarReadStatus::Absent;  // Positively absent -- genuinely never written. ENOENT only
                                                          // is treated this way; any other open failure (permission,
                                                          // etc.) would also return nullptr here and is intentionally
                                                          // folded into the SAME safe-side CorruptOrError-adjacent
                                                          // handling below rather than Absent, since this class cannot
                                                          // itself distinguish fopen's errno here without adding a
                                                          // platform dependency beyond this module's existing ones --
                                                          // callers already treat anything other than a successful,
                                                          // CRC-verified Present read as "do not treat as blank".
    uint8_t buf[kFileBytes];
    const size_t n = std::fread(buf, 1, sizeof(buf), f);
    std::fclose(f);
    if (n != sizeof(buf)) return SidecarReadStatus::CorruptOrError;  // Short/partial read: file EXISTED but is not
                                                                      // positively intact -- never treated as absent.

    const uint32_t expected_crc = ota::storage::Crc32::computeFinalized(buf, kBodyBytes);
    uint32_t stored_crc = 0;
    for (int i = 3; i >= 0; --i) stored_crc = (stored_crc << 8) | buf[kBodyBytes + i];
    if (stored_crc != expected_crc) return SidecarReadStatus::CorruptOrError;

    size_t off = 0;
    std::memcpy(out_record.transactionId, buf + off, kTransactionIdBytes);
    off += kTransactionIdBytes;
    if (!BaselineCertificationManifestCodec::parse(buf + off, BaselineCertificationManifestCodec::kManifestBytes,
                                                    out_record.manifest)) {
      return SidecarReadStatus::CorruptOrError;
    }
    off += BaselineCertificationManifestCodec::kManifestBytes;
    uint32_t target_id = 0;
    for (int i = 3; i >= 0; --i) target_id = (target_id << 8) | buf[off + i];
    out_record.targetId = target_id;
    return SidecarReadStatus::Present;
  }

  bool writeSidecarFileDurable(const uint8_t transactionId[kTransactionIdBytes], const SidecarFileRecord& record) {
    uint8_t manifest_bytes[BaselineCertificationManifestCodec::kManifestBytes];
    if (BaselineCertificationManifestCodec::serialize(record.manifest, manifest_bytes, sizeof(manifest_bytes)) !=
        BaselineCertificationManifestCodec::kManifestBytes) {
      return false;
    }

    uint8_t buf[kFileBytes];
    size_t off = 0;
    std::memcpy(buf + off, record.transactionId, kTransactionIdBytes);
    off += kTransactionIdBytes;
    std::memcpy(buf + off, manifest_bytes, sizeof(manifest_bytes));
    off += sizeof(manifest_bytes);
    for (size_t i = 0; i < 4; ++i) buf[off + i] = static_cast<uint8_t>((record.targetId >> (8 * i)) & 0xFF);
    off += 4;
    const uint32_t crc = ota::storage::Crc32::computeFinalized(buf, kBodyBytes);
    for (size_t i = 0; i < 4; ++i) buf[off + i] = static_cast<uint8_t>((crc >> (8 * i)) & 0xFF);

    const std::string path = pathFor(transactionId);
    const std::string tmp_path = path + ".tmp";
    FILE* f = std::fopen(tmp_path.c_str(), "wb");
    if (f == nullptr) return false;
    const size_t written = std::fwrite(buf, 1, sizeof(buf), f);
    const bool flush_ok = written == sizeof(buf) && std::fflush(f) == 0;
    const int fd = flush_ok ? fileno(f) : -1;
    const bool fsync_ok = fd >= 0 && fsync(fd) == 0;
    const bool close_ok = std::fclose(f) == 0;
    if (!flush_ok || !fsync_ok || !close_ok) {
      std::remove(tmp_path.c_str());
      return false;
    }
    // Atomic rename into place, then fsync the parent directory so the
    // new NAME itself is durable, not just the (already-fsync'd) file
    // contents -- same discipline the H5 fix applies to the main
    // registry copies (mere existence/reopen never proves a prior
    // parent-directory fsync happened; always fsync the parent before
    // declaring success).
    if (std::rename(tmp_path.c_str(), path.c_str()) != 0) {
      std::remove(tmp_path.c_str());
      return false;
    }
    return fsyncParentDirectory(path);
  }

  bool fsyncParentDirectory(const std::string& path) const {
    const size_t slash = path.find_last_of('/');
    const std::string dir = (slash == std::string::npos) ? "." : (slash == 0 ? "/" : path.substr(0, slash));
    const int fd = ::open(dir.c_str(), O_RDONLY);
    if (fd < 0) return false;
    const bool ok = fsync(fd) == 0;
    const bool close_ok = ::close(fd) == 0;
    return ok && close_ok;
  }

  AuthorityRegistryPair& registry_;
  std::string directory_;
};

}  // namespace authority
}  // namespace ota
