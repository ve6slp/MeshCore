#pragma once

// Real, file-backed implementation of a single AuthorityRegistryCopy. Each
// durable write follows the same write -> readback verify -> commit-marker
// pattern used by the on-device OTA journal (see ota/storage/Journal.h),
// translated to a plain append-only host file: every record is written,
// fsync'd, read back byte-for-byte, and only THEN is a trailing commit
// marker written and fsync'd. A record missing or failing that marker is
// never treated as valid regardless of what its CRC says.
//
// This class holds NO in-memory cache of registry state: every read scans
// the file from the beginning. That is deliberate -- it is what makes
// "close this object, construct a brand-new one against the same path"
// (used throughout test/test_lora_ota_authority for cold-reconstruction
// tests) a genuine cold read, not a reused RAM shortcut. The constructor
// performs zero I/O; the backing file is created lazily on first append.

#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>

#include "ota/authority/AuthorityRegistryPort.h"
#include "ota/storage/Crc32.h"

namespace ota {
namespace authority {

class FileAuthorityRegistryCopy : public AuthorityRegistryCopy {
public:
  explicit FileAuthorityRegistryCopy(std::string path) : path_(std::move(path)) {}

  // FOR TESTS ONLY: real production construction never calls this. Lets
  // a test genuinely fault a specific parent-directory fsync call (e.g.
  // "fail exactly the first one, succeed every later one") to prove the
  // H5 retry/reopen durability fix behaviorally -- never used to merely
  // introspect whether fsync was called.
  void setFsyncParentDirectoryOverrideForTests(std::function<bool(const std::string&)> override_fn) {
    fsync_parent_directory_override_for_tests_ = std::move(override_fn);
  }

  // FOR TESTS ONLY: real production construction never calls this. Lets
  // a test genuinely fault ONLY the commit-marker's own fsync call
  // (distinct from the data/CRC fsync earlier in the same appendSlot
  // call) -- see the H5 marker-invalidation comment on appendSlot below
  // for why that failure mode needs its own dedicated seam rather than
  // reusing fsyncParentDirectory's override.
  void setMarkerFsyncOverrideForTests(std::function<bool(int)> override_fn) {
    marker_fsync_override_for_tests_ = std::move(override_fn);
  }

  // FOR TESTS ONLY: real production construction never calls this. Lets
  // a test genuinely fault the POSITIVE re-confirmation fsync (the one
  // `confirmDurable()` itself performs right before any permission
  // release), independent of the original write-time fsync override
  // above -- proves "a later confirmDurable() call is denied, not just
  // the original append" and "a later confirmDurable() succeeding after
  // the underlying storage recovers genuinely un-denies release".
  void setConfirmDurableFsyncOverrideForTests(std::function<bool(int)> override_fn) {
    confirm_durable_fsync_override_for_tests_ = std::move(override_fn);
  }

  // Sol fe862c8 residual (H5): the positive storage barrier -- see the
  // contract comment on AuthorityRegistryCopy::confirmDurable(). Always
  // opens the backing file FRESH (no cached fd/state survives across
  // calls, so this is unaffected by what any earlier, possibly-failed
  // append attempt left behind in this object) and requires BOTH the
  // file's own fsync AND the parent directory's fsync to succeed RIGHT
  // NOW, not merely at original write time.
  bool confirmDurable() const override {
    errno = 0;
    FILE* f = std::fopen(path_.c_str(), "rb");
    if (f == nullptr) {
      // A genuinely-missing file has nothing to confirm -- callers that
      // expect a record to exist already learn that from reconcile()/
      // readLatest() returning NotFound; confirmDurable() itself must
      // not independently fabricate a pass for an absent file (that
      // would let an unwritten copy silently satisfy the barrier).
      return false;
    }
    const int fd = fileno(f);
    const bool fsync_ok =
        fd >= 0 && (confirm_durable_fsync_override_for_tests_ ? confirm_durable_fsync_override_for_tests_(fd)
                                                                : fsync(fd) == 0);
    std::fclose(f);
    if (!fsync_ok) return false;
    return fsyncParentDirectory(path_);
  }

  bool appendIssued(const AuthorityTransaction& txn) override {
    StoredTransactionRecord existing;
    bool corrupt = false;
    const bool found = readLatest(txn.transactionId, existing, corrupt);
    // CORRECTED per review: previously only `found` (a clean prior
    // Issued/transition record) blocked a fresh append; if this exact
    // transactionId already had UNEXPLAINED/unreadable later history
    // (`corrupt == true`, `found == false`), the old code issued a
    // brand-new Issued record right over it anyway, silently hiding the
    // fact that a corrupt record already existed under this id. Corrupt-
    // before-issuance must refuse the append outright, never pretend the
    // id was free.
    if (found || corrupt) {
      return false;
    }

    uint8_t payload[kMaxPayloadBytes] = {0};
    const size_t written = AuthorityCodec::serializeRecord(txn, payload, AuthorityCodec::kRecordBytes);
    if (written != AuthorityCodec::kRecordBytes) return false;
    return appendSlot(kKindIssued, payload, sizeof(payload));
  }

  bool appendStateTransition(const uint8_t transactionId[kTransactionIdBytes], TransactionState newState,
                              const uint8_t preparedRootDigestSha256[kDigestBytes], bool rootBound,
                              const uint8_t challenge[kChallengeBytes]) override {
    StoredTransactionRecord existing;
    bool corrupt = false;
    if (!readLatest(transactionId, existing, corrupt) || corrupt) return false;

    // Only a strict, single-step advance is ever accepted (defense in
    // depth: AuthorityCoordinator is expected to already enforce this).
    if (stateRank(newState) != stateRank(existing.state) + 1) return false;

    // ActivationSpent must always be rootBound -- never durably persist a
    // self-contradictory "spent but no root known" record.
    if (newState == TransactionState::ActivationSpent && !rootBound) return false;

    if (newState == TransactionState::ActivationSpent && existing.rootBound) {
      // Must activate the EXISTING matching prepared root, never a
      // different one (rule 5/6): reject silently-substituted roots here
      // too, not only in the coordinator. Only enforced when the prior
      // record actually bound a root already (a fresh ConsumedPrepared->
      // ActivationSpent advance is the FIRST time a root becomes known,
      // so there is nothing yet to conflict with).
      if (std::memcmp(preparedRootDigestSha256, existing.preparedRootDigestSha256, kDigestBytes) != 0) return false;
    }

    uint8_t payload[kMaxPayloadBytes] = {0};
    size_t pos = 0;
    std::memcpy(payload + pos, transactionId, kTransactionIdBytes);
    pos += kTransactionIdBytes;
    payload[pos++] = static_cast<uint8_t>(newState);
    payload[pos++] = rootBound ? 1 : 0;
    std::memcpy(payload + pos, preparedRootDigestSha256, kDigestBytes);
    pos += kDigestBytes;
    std::memcpy(payload + pos, challenge, kChallengeBytes);
    pos += kChallengeBytes;

    return appendSlot(kKindTransition, payload, sizeof(payload));
  }

  bool readLatest(const uint8_t transactionId[kTransactionIdBytes], StoredTransactionRecord& out,
                   bool& out_corrupt_but_present) const override {
    out_corrupt_but_present = false;
    bool found = false;
    bool any_invalid_slot_seen = false;

    const SlotFileScanStatus scan_status = forEachSlot([&](uint8_t kind, const uint8_t* payload, bool valid) {
      if (!valid) {
        any_invalid_slot_seen = true;
        return;
      }
      if (kind == kKindIssued) {
        AuthorityTransaction txn;
        if (AuthorityCodec::parseRecord(payload, AuthorityCodec::kRecordBytes, txn) != AuthorityDecodeError::None) {
          any_invalid_slot_seen = true;
          return;
        }
        if (std::memcmp(txn.transactionId, transactionId, kTransactionIdBytes) == 0) {
          out.txn = txn;
          out.state = TransactionState::Issued;
          out.rootBound = false;
          std::memset(out.preparedRootDigestSha256, 0, kDigestBytes);
          std::memset(out.challenge, 0, kChallengeBytes);
          found = true;
        }
      } else if (kind == kKindTransition) {
        if (std::memcmp(payload, transactionId, kTransactionIdBytes) != 0) return;
        const uint8_t state_raw = payload[kTransactionIdBytes];
        if (state_raw != static_cast<uint8_t>(TransactionState::ConsumedPrepared) &&
            state_raw != static_cast<uint8_t>(TransactionState::ActivationSpent)) {
          any_invalid_slot_seen = true;
          return;
        }
        const uint8_t root_bound_raw = payload[kTransactionIdBytes + 1];
        if (root_bound_raw != 0 && root_bound_raw != 1) {
          any_invalid_slot_seen = true;
          return;
        }
        if (!found) {
          // A transition with no preceding Issued record for this id is
          // unexplained history -- surface it as corruption, never as a
          // usable state.
          any_invalid_slot_seen = true;
          return;
        }
        out.state = static_cast<TransactionState>(state_raw);
        out.rootBound = root_bound_raw != 0;
        std::memcpy(out.preparedRootDigestSha256, payload + kTransactionIdBytes + 2, kDigestBytes);
        std::memcpy(out.challenge, payload + kTransactionIdBytes + 2 + kDigestBytes, kChallengeBytes);
      }
    });

    // H4 fix: a genuinely missing file is the ONLY case that may report
    // clean "not found" with no corruption. A ReadError (open failed for
    // a reason other than ENOENT, or a read failed mid-stream) must
    // ALWAYS surface as corrupt/Uncertain, regardless of anything that
    // happened to be accumulated into `found`/`any_invalid_slot_seen`
    // before the failure -- never silently reinterpreted as a clean,
    // virgin registry.
    if (scan_status == SlotFileScanStatus::GenuinelyMissing) {
      out_corrupt_but_present = false;
      return false;
    }
    if (scan_status == SlotFileScanStatus::ReadError) {
      out_corrupt_but_present = true;
      return false;
    }

    // CORRECTED per review: the old code returned `true` immediately once
    // an earlier valid record was `found`, WITHOUT ever propagating
    // `any_invalid_slot_seen` in that path. That meant a copy with a
    // valid, earlier Issued record followed by a LATER unreadable/corrupt
    // transition (e.g. a bit-flipped ActivationSpent slot) silently
    // reported back the stale Issued state as if it were the clean,
    // complete truth -- exactly the "one corrupt later Spent + stale
    // Issued other copy reopens prepare" scenario the review calls out.
    // Unknown later history must always surface as corruption, whether
    // or not an earlier record was also found: `reconcileCopies` already
    // treats `present && corrupt` as untrusted (not `present && !corrupt`
    // as valid), so this is safe to report unconditionally.
    out_corrupt_but_present = any_invalid_slot_seen;
    return found;
  }

  bool readLatestActivationForOwner(const AuthorityBinding& owner, StoredTransactionRecord& out,
                                     bool& out_corrupt_but_present) const override {
    bool any_invalid_slot_seen = false;
    std::vector<StoredTransactionRecord> all = scanAllRecords(any_invalid_slot_seen);

    bool found = false;
    for (const auto& rec : all) {
      if (rec.state != TransactionState::ActivationSpent) continue;
      // H1 fix: CertifyExistingBaseline is a narrower, non-lineage grant
      // (see AuthorityOperation's own comment) that deliberately never
      // enters the Commission/Repair/Rekey Issued->ConsumedPrepared->
      // ActivationSpent lifecycle and is never itself ActivationSpent in
      // practice -- but excluding it here explicitly, rather than
      // relying on that invariant holding elsewhere, keeps this
      // Commission/Repair/Rekey-only lineage scan correct even if that
      // ever changes. A signed baseline certificate must never be
      // mistaken for "this owner already has ActivationSpent history",
      // which would wrongly block a genuine first Commission.
      if (rec.txn.operation == AuthorityOperation::CertifyExistingBaseline) continue;
      if (!rec.txn.binding.sameOwnership(owner)) continue;
      if (!found || rec.txn.revision > out.txn.revision) {
        out = rec;
        found = true;
      }
    }
    out_corrupt_but_present = any_invalid_slot_seen;
    return found;
  }

  // H-finding fix: latest-revision record for this PHYSICAL device (any
  // fullPK, any state), used by rekeyExplicitly's fork-prevention fence
  // -- see AuthorityRegistryPort.h::readLatestPhysicalLineage. A pending
  // (Issued/ConsumedPrepared, not yet ActivationSpent) successor under a
  // DIFFERENT fullPK still counts here, unlike readLatestActivationForOwner
  // above which only ever sees ActivationSpent. If more than one DISTINCT
  // transactionId is found at the same highest revision for this
  // physical device, that is an unresolved fork within this single copy
  // -- surfaced as corrupt, never silently resolved by picking one.
  bool readLatestPhysicalLineage(const AuthorityBinding& physicalDevice, StoredTransactionRecord& out,
                                  bool& out_corrupt_but_present) const override {
    bool any_invalid_slot_seen = false;
    std::vector<StoredTransactionRecord> all = scanAllRecords(any_invalid_slot_seen);

    bool found = false;
    bool fork_at_highest_revision = false;
    for (const auto& rec : all) {
      // H1 fix: same CertifyExistingBaseline exclusion as
      // readLatestActivationForOwner above -- this scan exists purely to
      // fence Commission/Repair/Rekey forks, never to treat a baseline
      // certificate as bootstrap/lineage history for this physical
      // device.
      if (rec.txn.operation == AuthorityOperation::CertifyExistingBaseline) continue;
      // MAIN's binding clarification: the lifetime fork-fence key is
      // physical UID + fixed BOOT domain ONLY (samePhysicalLifetime) --
      // NOT the broader UID+domain+layout sameDeviceIdentity -- so a
      // relabeled profileId/layoutId on the same physical chip cannot
      // escape this scan and be mistaken for an unrelated device.
      if (!rec.txn.binding.samePhysicalLifetime(physicalDevice)) continue;
      if (!found || rec.txn.revision > out.txn.revision) {
        out = rec;
        found = true;
        fork_at_highest_revision = false;
      } else if (rec.txn.revision == out.txn.revision &&
                 std::memcmp(rec.txn.transactionId, out.txn.transactionId, kTransactionIdBytes) != 0) {
        // Two genuinely different transactions claim the same revision
        // for the same physical device -- a fork. Never silently keep
        // whichever happened to be scanned first.
        fork_at_highest_revision = true;
      }
    }
    if (fork_at_highest_revision) {
      any_invalid_slot_seen = true;
      found = false;
    }
    out_corrupt_but_present = any_invalid_slot_seen;
    return found;
  }

  // H3 fix: mirrors readLatestPhysicalLineage exactly, but filters by
  // sameOwnership (UID+fullPK+cryptoDomain+layout) instead of
  // sameDeviceIdentity (UID+cryptoDomain+layout only), and is used by
  // submitCommission's genesis fork-prevention fence -- see
  // AuthorityRegistryPort.h::reconcileOwnershipLineage.
  bool readLatestOwnershipLineage(const AuthorityBinding& owner, StoredTransactionRecord& out,
                                   bool& out_corrupt_but_present) const override {
    bool any_invalid_slot_seen = false;
    std::vector<StoredTransactionRecord> all = scanAllRecords(any_invalid_slot_seen);

    bool found = false;
    bool fork_at_highest_revision = false;
    for (const auto& rec : all) {
      // H1 fix: same CertifyExistingBaseline exclusion -- a signed
      // baseline certificate (Issued forever, never advances) must never
      // be mistaken for an existing Commission genesis when fencing a
      // brand-new first Commission for this exact ownership.
      if (rec.txn.operation == AuthorityOperation::CertifyExistingBaseline) continue;
      if (!rec.txn.binding.sameOwnership(owner)) continue;
      if (!found || rec.txn.revision > out.txn.revision) {
        out = rec;
        found = true;
        fork_at_highest_revision = false;
      } else if (rec.txn.revision == out.txn.revision &&
                 std::memcmp(rec.txn.transactionId, out.txn.transactionId, kTransactionIdBytes) != 0) {
        fork_at_highest_revision = true;
      }
    }
    if (fork_at_highest_revision) {
      any_invalid_slot_seen = true;
      found = false;
    }
    out_corrupt_but_present = any_invalid_slot_seen;
    return found;
  }

  const std::string& path() const { return path_; }

private:
  static constexpr uint8_t kKindIssued = 1;
  static constexpr uint8_t kKindTransition = 2;
  static constexpr size_t kMaxPayloadBytes = AuthorityCodec::kRecordBytes;  // 238; transitions are padded to this.
  static constexpr uint32_t kCommitMarker = 0xC001DA7Eu;

  // slot = kind(1) + payload(kMaxPayloadBytes) + crc32(4) + marker(4)
  static constexpr size_t kSlotBytes = 1 + kMaxPayloadBytes + 4 + 4;

  // H4 fix: a scan can end in exactly one of three distinguishable ways,
  // and callers must never conflate them. `GenuinelyMissing` is the ONLY
  // status that may ever be treated as a clean, empty, nothing-recorded
  // registry -- it is reported strictly when `fopen` fails with ENOENT
  // (the file positively does not exist). Any OTHER open/read failure
  // (permission denied, too many open files, a mid-stream I/O error) is
  // `ReadError` and must be surfaced as Uncertain/corrupt, never silently
  // treated the same as a virgin file: a transient failure that LOOKED
  // like "no history here" would be indistinguishable from fabricated
  // first-use proof.
  enum class SlotFileScanStatus : uint8_t { Ok = 0, GenuinelyMissing = 1, ReadError = 2 };

  // If the file's length is not an exact multiple of kSlotBytes, a prior
  // append was torn (interrupted before completing a full slot). Such a
  // partial tail never reached its CRC+commit-marker bytes (the LAST
  // bytes any slot writes) and can therefore never itself represent
  // committed data under this class's own write-readback-marker
  // discipline -- but that does NOT mean it is safe to blindly discard.
  //
  // CORRECTED per Sol29 review ("unconditional truncation... no
  // 'successful append unreadable'"): the previous version truncated any
  // misaligned tail unconditionally, on the theory that an incomplete
  // slot can never be valid anyway. That reasoning skips a real risk --
  // the torn bytes might be the START of a write that was ALSO, in
  // parallel/subsequently, further along on the genuinely-synced copy of
  // this same transaction (i.e. this copy briefly lagged and then a
  // crash interrupted the very write that would have caught it up); a
  // caller must never have that ambiguity silently resolved toward "this
  // copy's history is exactly what forEachSlot can cleanly read". The
  // ONLY tail content this class can positively PROVE was never actually
  // written (as opposed to a genuine partial write of real bytes) is a
  // tail that is entirely zero -- which is exactly what a freshly-
  // extended-but-unwritten region of a plain host file looks like,
  // analogous to a NAND erased-state convention, but chosen as all-zero
  // because that is what this class's own zero-initialized payload
  // buffers start as and nothing else in this format ever intentionally
  // writes an all-zero tail shorter than a full slot. Any NONZERO byte in
  // the torn tail is refused outright (return false) rather than
  // silently truncated -- the caller must surface this as append
  // failure/Uncertain, never as a quiet "successful append" over
  // unexplained bytes.
  bool repairTornTailIfAny() {
    errno = 0;
    FILE* check = std::fopen(path_.c_str(), "rb");
    if (check == nullptr) {
      // H4 fix: only a positively-confirmed absent file is "nothing to
      // repair". Any other open failure (permission denied, too many
      // open files, ...) must refuse rather than silently proceed as if
      // this copy were virgin -- an explicit check must never be able to
      // masquerade an unreadable-but-present file as an empty one.
      return errno == ENOENT;
    }
    if (std::fseek(check, 0, SEEK_END) != 0) { std::fclose(check); return false; }
    const long size = std::ftell(check);
    if (size < 0) { std::fclose(check); return false; }

    const long aligned = (size / static_cast<long>(kSlotBytes)) * static_cast<long>(kSlotBytes);
    if (aligned == size) { std::fclose(check); return true; }  // Already aligned: nothing torn.

    const long torn_len = size - aligned;
    std::vector<uint8_t> torn(static_cast<size_t>(torn_len));
    bool tail_readable = std::fseek(check, aligned, SEEK_SET) == 0 &&
                          std::fread(torn.data(), 1, torn.size(), check) == torn.size();
    std::fclose(check);
    if (!tail_readable) return false;

    for (uint8_t b : torn) {
      if (b != 0x00) {
        // Cannot positively prove this tail was never written to; refuse
        // rather than fabricate a "clean, ready-to-append" file.
        return false;
      }
    }

    if (::truncate(path_.c_str(), static_cast<off_t>(aligned)) != 0) return false;
    // Durably fsync the truncation itself before any new data is written
    // on top of it.
    FILE* f = std::fopen(path_.c_str(), "r+b");
    if (f == nullptr) return false;
    const int fd = fileno(f);
    const bool ok = fd >= 0 && fsync(fd) == 0;
    std::fclose(f);
    return ok;
  }

  // H5 fix (revised per review): fsync'ing a file's own contents durably
  // persists ITS bytes, but the PARENT DIRECTORY's own entry pointing at
  // it must independently be fsync'd too -- most POSIX filesystems do
  // not implicitly persist a new/renamed directory entry just because
  // the file it names was fsync'd.
  //
  // This was previously gated on a freshly-`stat()`ed `existed_before`
  // flag, called only "the first time a path is created" -- but a mere
  // `stat()` finding the file present proves NOTHING about whether any
  // PRIOR parent-directory fsync actually succeeded: if the first
  // creating append's directory fsync failed (ENOSPC/EIO/etc, itself
  // correctly reported as a failed append), the file still exists on
  // disk afterward. Any later retry/reopen/repair call (e.g.
  // repairReplicaIssued, lineage repair) then finds `existed_before ==
  // true` and skips the directory fsync FOREVER, even though the
  // directory entry durability was never actually confirmed. A local
  // "already synced" flag has the identical defect: it does not survive
  // process reopen/retry either.
  //
  // The only invariant that is actually safe against reopen/retry/crash
  // is: every successful append durably fsyncs the parent directory
  // before being allowed to report success, unconditionally. This is a
  // deliberately simple, conservative, always-pay host-side durability
  // cost (no radio/CPU budget constraint applies to the host registry
  // tooling) rather than a per-path cached/tracked state that could be
  // lost or bypassed.
  bool fsyncParentDirectory(const std::string& path) const {
    // FOR TESTS ONLY seam: when set, this REPLACES the real syscall path
    // entirely for exactly this call -- used to genuinely fault "the
    // first dir fsync" (or any specific call) and observe real
    // behavioral consequences (no permit released, retry/repair
    // recovers), never to merely record that a real fsync happened.
    if (fsync_parent_directory_override_for_tests_) {
      return fsync_parent_directory_override_for_tests_(path);
    }
    const size_t slash = path.find_last_of('/');
    const std::string dir = (slash == std::string::npos) ? "." : (slash == 0 ? "/" : path.substr(0, slash));
    const int fd = ::open(dir.c_str(), O_RDONLY);
    if (fd < 0) return false;
    const bool ok = fsync(fd) == 0;
    const bool close_ok = ::close(fd) == 0;
    return ok && close_ok;
  }

  bool appendSlot(uint8_t kind, const uint8_t* payload, size_t payload_len) {
    if (payload_len != kMaxPayloadBytes) return false;
    if (!repairTornTailIfAny()) return false;

    std::vector<uint8_t> body(1 + kMaxPayloadBytes);
    body[0] = kind;
    std::memcpy(body.data() + 1, payload, kMaxPayloadBytes);
    const uint32_t crc = ota::storage::Crc32::computeFinalized(body.data(), body.size());
    uint8_t crc_bytes[4] = {
        static_cast<uint8_t>((crc >> 24) & 0xFFu), static_cast<uint8_t>((crc >> 16) & 0xFFu),
        static_cast<uint8_t>((crc >> 8) & 0xFFu), static_cast<uint8_t>(crc & 0xFFu),
    };

    FILE* f = std::fopen(path_.c_str(), "ab+");
    if (f == nullptr) return false;

    if (std::fseek(f, 0, SEEK_END) != 0) { std::fclose(f); return false; }
    const long offset = std::ftell(f);
    if (offset < 0) { std::fclose(f); return false; }

    bool ok = std::fwrite(body.data(), 1, body.size(), f) == body.size();
    ok = ok && std::fwrite(crc_bytes, 1, sizeof(crc_bytes), f) == sizeof(crc_bytes);
    ok = ok && std::fflush(f) == 0;
    if (ok) {
      const int fd = fileno(f);
      ok = fd >= 0 && fsync(fd) == 0;
    }

    if (ok) {
      // Readback verification before the commit marker is ever written.
      std::vector<uint8_t> reread(body.size() + sizeof(crc_bytes));
      ok = std::fseek(f, offset, SEEK_SET) == 0 &&
           std::fread(reread.data(), 1, reread.size(), f) == reread.size();
      if (ok) {
        ok = std::memcmp(reread.data(), body.data(), body.size()) == 0 &&
             std::memcmp(reread.data() + body.size(), crc_bytes, sizeof(crc_bytes)) == 0;
      }
    }

    if (!ok) {
      std::fclose(f);
      return false;
    }

    uint8_t marker_bytes[4] = {
        static_cast<uint8_t>((kCommitMarker >> 24) & 0xFFu), static_cast<uint8_t>((kCommitMarker >> 16) & 0xFFu),
        static_cast<uint8_t>((kCommitMarker >> 8) & 0xFFu), static_cast<uint8_t>(kCommitMarker & 0xFFu),
    };
    const long marker_offset = offset + static_cast<long>(body.size() + sizeof(crc_bytes));
    ok = std::fseek(f, marker_offset, SEEK_SET) == 0 &&
         std::fwrite(marker_bytes, 1, sizeof(marker_bytes), f) == sizeof(marker_bytes) &&
         std::fflush(f) == 0;
    if (ok) {
      const int fd = fileno(f);
      ok = fd >= 0 && (marker_fsync_override_for_tests_ ? marker_fsync_override_for_tests_(fd) : fsync(fd) == 0);
    }
    if (!ok) {
      // Sol fe862c8 residual (H5): the marker bytes may already have
      // been fwrite+fflush'd (handed to the OS page cache) by the time
      // this fsync failure is observed -- an fsync() failure is a
      // durability-CONFIRMATION failure, not proof the preceding
      // write()-to-pagecache step was undone. A best-effort "poison the
      // marker" overwrite was tried here previously and is NOT a valid
      // fix: that corrective write/fsync can itself fail, or the process
      // can die between the original failure and the correction,
      // leaving the exact same byte-perfect-but-unconfirmed marker
      // readable regardless. This method still correctly reports the
      // append as failed (`return false` below) -- the actual close of
      // the gap is NOT here: it is AuthorityRegistryCopy::confirmDurable(),
      // which every authority-permission-release call site must invoke
      // (fresh, immediately before release, every time -- including
      // after close/reopen and repair) rather than trusting a plain
      // readLatest()/reconcile() alone. See confirmDurable()'s contract
      // comment on AuthorityRegistryPort.h for why a LATER fresh fsync
      // retry is the only invariant that is actually safe here.
      std::fclose(f);
      return false;
    }
    // H5 fix: a failing fclose (buffered write-back errors, e.g. ENOSPC,
    // can surface only here) must never be silently discarded -- fold it
    // into the reported result rather than trusting the pre-close `ok`
    // alone.
    const bool close_ok = std::fclose(f) == 0;
    if (!ok || !close_ok) return false;

    // Unconditional: always fsync the parent directory before this
    // append may be reported as durable, regardless of whether the file
    // "already existed" by the time we got here -- see the comment on
    // fsyncParentDirectory for why existence alone proves nothing about
    // prior directory-entry durability.
    if (!fsyncParentDirectory(path_)) return false;
    return true;
  }

  // Shared scan used by readLatestActivationForOwner and
  // readLatestPhysicalLineage: builds the full in-memory Issued+
  // transitions view of this copy, folding every transition onto its
  // matching Issued record (by transactionId) exactly as
  // forEachSlot/readLatest already do. Any unreadable slot or orphan
  // transition sets `any_invalid_slot_seen = true` -- callers must
  // propagate that as corruption, never silently drop it. H4 fix: a
  // ReadError from the underlying scan (as opposed to a positively
  // confirmed missing file) is ALSO folded into `any_invalid_slot_seen`
  // here, so every caller of this shared helper automatically inherits
  // the same "open/read failure is Uncertain, never empty" guarantee
  // without needing its own separate plumbing.
  std::vector<StoredTransactionRecord> scanAllRecords(bool& any_invalid_slot_seen) const {
    any_invalid_slot_seen = false;
    std::vector<StoredTransactionRecord> all;
    const SlotFileScanStatus scan_status = forEachSlot([&](uint8_t kind, const uint8_t* payload, bool valid) {
      if (!valid) {
        any_invalid_slot_seen = true;
        return;
      }
      if (kind == kKindIssued) {
        AuthorityTransaction txn;
        if (AuthorityCodec::parseRecord(payload, AuthorityCodec::kRecordBytes, txn) != AuthorityDecodeError::None) {
          any_invalid_slot_seen = true;
          return;
        }
        StoredTransactionRecord rec;
        rec.txn = txn;
        rec.state = TransactionState::Issued;
        all.push_back(rec);
      } else if (kind == kKindTransition) {
        bool matched_any = false;
        for (auto& rec : all) {
          if (std::memcmp(rec.txn.transactionId, payload, kTransactionIdBytes) == 0) {
            matched_any = true;
            const uint8_t state_raw = payload[kTransactionIdBytes];
            const uint8_t root_bound_raw = payload[kTransactionIdBytes + 1];
            if ((state_raw == static_cast<uint8_t>(TransactionState::ConsumedPrepared) ||
                 state_raw == static_cast<uint8_t>(TransactionState::ActivationSpent)) &&
                (root_bound_raw == 0 || root_bound_raw == 1)) {
              rec.state = static_cast<TransactionState>(state_raw);
              rec.rootBound = root_bound_raw != 0;
              std::memcpy(rec.preparedRootDigestSha256, payload + kTransactionIdBytes + 2, kDigestBytes);
              std::memcpy(rec.challenge, payload + kTransactionIdBytes + 2 + kDigestBytes, kChallengeBytes);
            } else {
              any_invalid_slot_seen = true;
            }
          }
        }
        if (!matched_any) {
          // A transition with no preceding Issued record for this id is
          // unexplained history, same as readLatest's identical rule.
          any_invalid_slot_seen = true;
        }
      }
    });
    if (scan_status == SlotFileScanStatus::ReadError) any_invalid_slot_seen = true;
    return all;
  }

  // Scans the whole file from offset 0, invoking `fn(kind, payload, valid)`
  // for every complete slot position. `valid` is false if the CRC or
  // commit marker did not check out (payload contents are undefined in
  // that case and must not be interpreted). Stops cleanly at the first
  // incomplete (torn-write) slot at end-of-file.
  //
  // H4 fix: returns a typed SlotFileScanStatus rather than silently
  // treating every open/read outcome the same way. `errno` is captured
  // IMMEDIATELY after the failing `fopen` call, before any other libc
  // call can clobber it.
  template <typename Fn>
  SlotFileScanStatus forEachSlot(Fn fn) const {
    errno = 0;
    FILE* f = std::fopen(path_.c_str(), "rb");
    if (f == nullptr) {
      const int open_errno = errno;
      // Only a positively-confirmed "this path does not exist" may be
      // treated as a clean, virgin registry. Any other reason `fopen`
      // failed (permission denied, too many open files, a transient I/O
      // error, ...) must be surfaced as Uncertain, never silently
      // reinterpreted as "nothing recorded here".
      return (open_errno == ENOENT) ? SlotFileScanStatus::GenuinelyMissing : SlotFileScanStatus::ReadError;
    }

    std::vector<uint8_t> slot(kSlotBytes);
    for (;;) {
      const size_t got = std::fread(slot.data(), 1, kSlotBytes, f);
      if (got != kSlotBytes) {
        // A short read at end-of-file is the expected, clean way this
        // loop terminates (including a torn trailing slot, handled
        // separately by repairTornTailIfAny). A short read caused by a
        // genuine I/O error (ferror set) is NOT clean and must never be
        // silently treated the same as "scan finished normally".
        const bool had_error = std::ferror(f) != 0;
        std::fclose(f);
        return had_error ? SlotFileScanStatus::ReadError : SlotFileScanStatus::Ok;
      }
      const uint8_t kind = slot[0];
      const uint8_t* payload = slot.data() + 1;
      const uint32_t stored_crc =
          (static_cast<uint32_t>(slot[1 + kMaxPayloadBytes]) << 24) |
          (static_cast<uint32_t>(slot[1 + kMaxPayloadBytes + 1]) << 16) |
          (static_cast<uint32_t>(slot[1 + kMaxPayloadBytes + 2]) << 8) |
          static_cast<uint32_t>(slot[1 + kMaxPayloadBytes + 3]);
      const uint32_t computed_crc = ota::storage::Crc32::computeFinalized(slot.data(), 1 + kMaxPayloadBytes);
      const uint32_t stored_marker =
          (static_cast<uint32_t>(slot[1 + kMaxPayloadBytes + 4]) << 24) |
          (static_cast<uint32_t>(slot[1 + kMaxPayloadBytes + 5]) << 16) |
          (static_cast<uint32_t>(slot[1 + kMaxPayloadBytes + 6]) << 8) |
          static_cast<uint32_t>(slot[1 + kMaxPayloadBytes + 7]);

      const bool valid = (stored_crc == computed_crc) && (stored_marker == kCommitMarker) &&
                          (kind == kKindIssued || kind == kKindTransition);
      fn(kind, payload, valid);
    }
  }

  std::string path_;
  std::function<bool(const std::string&)> fsync_parent_directory_override_for_tests_;
  std::function<bool(int)> marker_fsync_override_for_tests_;
  std::function<bool(int)> confirm_durable_fsync_override_for_tests_;
};

}  // namespace authority
}  // namespace ota
