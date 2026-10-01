#pragma once

// Canonical, fixed-width, bounds-checked serialization of an
// AuthorityTransaction. This is the EXACT byte sequence the issuer
// signature covers (see kSignedMessageBytes) and the exact on-the-wire /
// on-disk record layout (see kRecordBytes, which appends the signature
// itself). The signature, and any later receipt/publication marker, are
// deliberately excluded from the signed message -- a signature cannot
// cover itself, and receipts are verified against this same canonical
// message independently (see AuthorityCoordinator.h).
//
// Big-endian throughout, via the same bounds-checked cursors the rest of
// the OTA protocol uses (OtaByteStream.h) -- no reinterpret_cast/memcpy of
// multi-byte integers, no heap allocation, no unbounded arrays. The
// signed message is 174 bytes and the full durable record (signed
// message + 64-byte signature) is 238 bytes, comfortably inside an 8 KiB
// task stack.
//
// Astra29: this record deliberately carries NO "expected root digest"
// field (removed from AuthorityTransaction itself -- see
// AuthorityTypes.h). `computeRecordDigestSha256` below produces A, the
// digest of the EXACT signed record (including the signature), which is
// the value every wrapper (ActivationAuthorizationV1::grantDigestSha256,
// BootFloorActivationReceipt::authorityTransactionDigestSha256) must bind
// to -- never the manifest digest (M), and never a not-yet-known root
// digest (R, see PreparedRootCommitment.h).

#include <stdint.h>
#include <stddef.h>
#include "ota/authority/AuthorityTypes.h"
#include "ota/protocol/OtaByteStream.h"
#include "ota/trust/Sha256.h"

namespace ota {
namespace authority {

enum class AuthorityDecodeError : uint8_t {
  None = 0,
  TooShort = 1,
  TooLong = 2,
  InvalidOperation = 3,
  InvalidCryptoForm = 4,
  InvalidGroupSelectorForPairwise = 5,
};

class AuthorityCodec {
public:
  // uid(8) + fullPK(32) + form(1) + selector(2) + profile(4) + layout(4) +
  // role(4) + consentOwner(32) = kBindingBytes (87 bytes), reused verbatim
  // by ActivationAuthorizationCodec.h's `expectedBinding` field so the two
  // codecs can never silently drift apart on how a binding is encoded.
  static constexpr size_t kBindingBytes = 87;

  // kBindingBytes(87) + operation(1) + txnId(16) + revision(4) +
  // predecessor(16) + manifestDigest(32) + txFloor(4) + rxFloor(4) +
  // issuerKeyId(2) + issuedAt(8) = 174 bytes. (Astra29: the prior
  // 206-byte layout also carried a 32-byte expectedRootDigestSha256
  // field, now removed entirely.)
  static constexpr size_t kSignedMessageBytes = 174;
  static constexpr size_t kRecordBytes = kSignedMessageBytes + kSignatureBytes;  // 238.

  // Serializes only the binding fields, in the exact canonical order/
  // width every signed message and every wrapper signature that binds a
  // full AuthorityBinding (e.g. ActivationAuthorizationV1::expectedBinding)
  // must use. Exposed publicly so no second, potentially-drifting copy of
  // this encoding is ever hand-written elsewhere.
  static bool writeBindingFields(meshcore::ota::protocol::OtaBoundedWriter& writer, const AuthorityBinding& binding) {
    if (!writer.putBytes(binding.hardwareUid, kHardwareUidBytes)) return false;
    if (!writer.putBytes(binding.meshFullPublicKey, kPublicKeyBytes)) return false;
    if (!writer.putU8(static_cast<uint8_t>(binding.cryptoDomain.form))) return false;
    if (!writer.putU16(binding.cryptoDomain.groupSelector)) return false;
    if (!writer.putU32(binding.profileId)) return false;
    if (!writer.putU32(binding.layoutId)) return false;
    if (!writer.putU32(binding.historicalInitialRoleId)) return false;
    if (!writer.putBytes(binding.consentOwnerPublicKey, kPublicKeyBytes)) return false;
    return true;
  }

  // Parses the binding fields in the same canonical order, failing
  // closed with the same specific error codes parseRecord already used
  // inline for this (kept identical so this refactor changes no
  // observable behavior).
  static AuthorityDecodeError readBindingFields(meshcore::ota::protocol::OtaBoundedReader& reader, AuthorityBinding& out) {
    if (!reader.getBytes(out.hardwareUid, kHardwareUidBytes)) return AuthorityDecodeError::TooShort;
    if (!reader.getBytes(out.meshFullPublicKey, kPublicKeyBytes)) return AuthorityDecodeError::TooShort;

    uint8_t form_raw = 0;
    if (!reader.getU8(form_raw)) return AuthorityDecodeError::TooShort;
    if (form_raw != static_cast<uint8_t>(meshcore::ota::runtime::OtaAeadForm::Pairwise) &&
        form_raw != static_cast<uint8_t>(meshcore::ota::runtime::OtaAeadForm::Group)) {
      return AuthorityDecodeError::InvalidCryptoForm;
    }
    out.cryptoDomain.form = static_cast<meshcore::ota::runtime::OtaAeadForm>(form_raw);

    uint16_t selector = 0;
    if (!reader.getU16(selector)) return AuthorityDecodeError::TooShort;
    if (out.cryptoDomain.form == meshcore::ota::runtime::OtaAeadForm::Pairwise && selector != 0) {
      return AuthorityDecodeError::InvalidGroupSelectorForPairwise;
    }
    out.cryptoDomain.groupSelector = selector;

    uint32_t profile = 0, layout = 0, role = 0;
    if (!reader.getU32(profile) || !reader.getU32(layout) || !reader.getU32(role)) {
      return AuthorityDecodeError::TooShort;
    }
    out.profileId = profile;
    out.layoutId = layout;
    out.historicalInitialRoleId = role;

    if (!reader.getBytes(out.consentOwnerPublicKey, kPublicKeyBytes)) return AuthorityDecodeError::TooShort;
    return AuthorityDecodeError::None;
  }

  // Serializes only the fields the issuer signature covers. Returns the
  // number of bytes written (always kSignedMessageBytes on success) or 0
  // on any capacity failure.
  static size_t serializeSignedMessage(const AuthorityTransaction& txn, uint8_t* out, size_t out_len) {
    meshcore::ota::protocol::OtaBoundedWriter writer(out, out_len);
    if (!writeSignedFields(writer, txn)) return 0;
    return writer.size();
  }

  // Serializes the full durable record (signed message + signature).
  static size_t serializeRecord(const AuthorityTransaction& txn, uint8_t* out, size_t out_len) {
    meshcore::ota::protocol::OtaBoundedWriter writer(out, out_len);
    if (!writeSignedFields(writer, txn)) return 0;
    if (!writer.putBytes(txn.issuerSignatureEd25519, kSignatureBytes)) return 0;
    return writer.size();
  }

  // Computes A = SHA256(the EXACT kRecordBytes durable record, INCLUDING
  // the issuer signature). This is the digest every wrapper that binds
  // "this exact signed grant" (ActivationAuthorizationV1::
  // grantDigestSha256, BootFloorActivationReceipt::
  // authorityTransactionDigestSha256) must use -- never
  // txn.manifestDigestSha256 (M, policy only) and never a bounded-digest
  // record with the signature stripped. Returns false only if the
  // record itself fails to serialize (never silently returns a
  // zero-filled digest).
  static bool computeRecordDigestSha256(const AuthorityTransaction& txn, uint8_t out_digest[kDigestBytes]) {
    uint8_t record[kRecordBytes];
    if (serializeRecord(txn, record, sizeof(record)) != kRecordBytes) return false;
    ota::trust::Sha256::hash(record, sizeof(record), out_digest);
    return true;
  }

  // Parses a full durable record back into `out`. Fails closed (returns a
  // specific, non-None error and leaves `out` default-constructed) on any
  // malformed, truncated, or semantically invalid input -- never
  // partially populates `out` on failure.
  static AuthorityDecodeError parseRecord(const uint8_t* in, size_t in_len, AuthorityTransaction& out) {
    // Astra29: this also intentionally covers legacy-format rejection --
    // a 270-byte record produced by the removed expectedRootDigestSha256
    // layout is neither silently reinterpreted nor truncated; it fails
    // closed with the same explicit, typed TooLong error any other
    // malformed input would.
    if (in_len < kRecordBytes) return AuthorityDecodeError::TooShort;
    if (in_len > kRecordBytes) return AuthorityDecodeError::TooLong;

    AuthorityTransaction parsed;
    meshcore::ota::protocol::OtaBoundedReader reader(in, kRecordBytes);

    const AuthorityDecodeError binding_error = readBindingFields(reader, parsed.binding);
    if (binding_error != AuthorityDecodeError::None) return binding_error;

    uint8_t operation_raw = 0;
    if (!reader.getU8(operation_raw)) return AuthorityDecodeError::TooShort;
    if (!isValidAuthorityOperation(operation_raw)) return AuthorityDecodeError::InvalidOperation;
    parsed.operation = static_cast<AuthorityOperation>(operation_raw);

    if (!reader.getBytes(parsed.transactionId, kTransactionIdBytes)) return AuthorityDecodeError::TooShort;

    uint32_t revision = 0;
    if (!reader.getU32(revision)) return AuthorityDecodeError::TooShort;
    parsed.revision = revision;

    if (!reader.getBytes(parsed.predecessorTransactionId, kTransactionIdBytes)) return AuthorityDecodeError::TooShort;
    if (!reader.getBytes(parsed.manifestDigestSha256, kDigestBytes)) return AuthorityDecodeError::TooShort;

    uint32_t tx_floor = 0, rx_floor = 0;
    if (!reader.getU32(tx_floor) || !reader.getU32(rx_floor)) return AuthorityDecodeError::TooShort;
    parsed.initialTxSequenceFloor = tx_floor;
    parsed.initialRxReplayFloor = rx_floor;

    uint16_t issuer_key_id = 0;
    if (!reader.getU16(issuer_key_id)) return AuthorityDecodeError::TooShort;
    parsed.issuerKeyId = issuer_key_id;

    uint64_t issued_at = 0;
    if (!getU64(reader, issued_at)) return AuthorityDecodeError::TooShort;
    parsed.issuedAtUnixSeconds = issued_at;

    if (!reader.getBytes(parsed.issuerSignatureEd25519, kSignatureBytes)) return AuthorityDecodeError::TooShort;

    out = parsed;
    return AuthorityDecodeError::None;
  }

private:
  static bool writeSignedFields(meshcore::ota::protocol::OtaBoundedWriter& writer, const AuthorityTransaction& txn) {
    if (!writeBindingFields(writer, txn.binding)) return false;
    if (!writer.putU8(static_cast<uint8_t>(txn.operation))) return false;
    if (!writer.putBytes(txn.transactionId, kTransactionIdBytes)) return false;
    if (!writer.putU32(txn.revision)) return false;
    if (!writer.putBytes(txn.predecessorTransactionId, kTransactionIdBytes)) return false;
    if (!writer.putBytes(txn.manifestDigestSha256, kDigestBytes)) return false;
    if (!writer.putU32(txn.initialTxSequenceFloor)) return false;
    if (!writer.putU32(txn.initialRxReplayFloor)) return false;
    if (!writer.putU16(txn.issuerKeyId)) return false;
    if (!putU64(writer, txn.issuedAtUnixSeconds)) return false;
    return true;
  }

  static bool putU64(meshcore::ota::protocol::OtaBoundedWriter& writer, uint64_t v) {
    if (!writer.putU32(static_cast<uint32_t>(v >> 32))) return false;
    if (!writer.putU32(static_cast<uint32_t>(v & 0xFFFFFFFFu))) return false;
    return true;
  }

  static bool getU64(meshcore::ota::protocol::OtaBoundedReader& reader, uint64_t& out) {
    uint32_t hi = 0, lo = 0;
    if (!reader.getU32(hi) || !reader.getU32(lo)) return false;
    out = (static_cast<uint64_t>(hi) << 32) | static_cast<uint64_t>(lo);
    return true;
  }
};

}  // namespace authority
}  // namespace ota
