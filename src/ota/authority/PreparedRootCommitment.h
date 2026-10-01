#pragma once

// Canonical, domain-separated commitment formula for R, the "prepared
// store root" digest:
//
//   R = SHA256(NO_NUL domain-literal || BE32(length(P)) || P)
//
// where P is a versioned, bounded, immutable set of prepared facts a
// real device/store persists BEFORE activation is permitted -- the full
// signed grant record (A), the manifest binding (M), the full binding
// (UID/fullPK/domain/profile/layout/initialRole/consentOwner), the
// txn/revision/predecessor, the device's own genuinely-generated store
// identity, and the exact initial seed/repair commitments -- EXCLUDING
// only proof-overlay fields (prepare/ACK/activate proofs, the boot
// receipt, R itself, and activation markers), per the approved Astra29
// correction.
//
// This header defines ONLY the commitment formula. The real content/
// encoding of P is real Store/Firmware's integration responsibility --
// this module holds no actual on-device storage and fabricates no P
// bytes of its own; DeviceAuthorityMaintenance::stageRoot (see
// DeviceAuthorityGuard.h) is the seam a real integrator wires to produce
// P and call computeDigestSha256 over it.
//
// Uses streaming SHA-256 (update/finish) rather than one contiguous
// buffer, so P is never required to be copied into a single on-stack
// array here regardless of its real size -- keeping this helper itself
// well inside the 8 KiB task-stack budget even though P's own real size
// is Store's concern, not this formula's.

#include <stdint.h>
#include <stddef.h>
#include "ota/trust/Sha256.h"

namespace ota {
namespace authority {

class PreparedRootCommitment {
public:
  static const char* domain() { return "MeshCore/OTA/prepared-store-root/v1"; }
  static constexpr size_t kDomainBytes = 35;  // strlen(domain()), NO_NUL (verified via len()).

  // Bounded, explicit error-result seam: computeDigestSha256 below never
  // silently narrows an out-of-range length, never hashes a null pointer
  // paired with a positive length (this used to be swallowed by skipping
  // the sha.update(p, ...) call while STILL hashing the mismatched BE32
  // length, producing a digest that pretends P was present when it
  // wasn't -- a real defect, now refused outright), and never writes to
  // out_digest on refusal.
  enum class Result {
    kOk = 0,
    kNullPointerWithPositiveLength,  // p == nullptr but p_len > 0: refuse, do not hash.
    kLengthExceedsUint32,            // p_len would silently narrow when packed into BE32(len(P)).
    kNullOutDigest,                  // out_digest == nullptr: nowhere safe to write the result.
  };

  // Computes R = SHA256(domain || BE32(len(p)) || p) via incremental
  // hashing (no single buffer sized to hold domain+len+p is ever formed).
  // On any Result other than kOk, out_digest is left completely untouched
  // and p is never read -- callers MUST check the returned Result before
  // trusting out_digest.
  static Result computeDigestSha256(const uint8_t* p, size_t p_len, uint8_t out_digest[32]) {
    if (out_digest == nullptr) return Result::kNullOutDigest;
    if (p == nullptr && p_len > 0) return Result::kNullPointerWithPositiveLength;
    // Checked BEFORE any read of p: an attacker/caller-supplied impossible
    // length is rejected on the length value alone, never by attempting
    // to allocate or read p_len bytes first.
    if (static_cast<uint64_t>(p_len) > static_cast<uint64_t>(UINT32_MAX)) {
      return Result::kLengthExceedsUint32;
    }

    ota::trust::Sha256 sha;
    sha.update(reinterpret_cast<const uint8_t*>(domain()), kDomainBytes);
    const uint8_t be_len[4] = {
        static_cast<uint8_t>((static_cast<uint32_t>(p_len) >> 24) & 0xFFu),
        static_cast<uint8_t>((static_cast<uint32_t>(p_len) >> 16) & 0xFFu),
        static_cast<uint8_t>((static_cast<uint32_t>(p_len) >> 8) & 0xFFu),
        static_cast<uint8_t>(static_cast<uint32_t>(p_len) & 0xFFu),
    };
    sha.update(be_len, sizeof(be_len));
    if (p_len > 0) sha.update(p, p_len);  // p is known non-null here (guarded above).
    sha.finish(out_digest);
    return Result::kOk;
  }
};

}  // namespace authority
}  // namespace ota
