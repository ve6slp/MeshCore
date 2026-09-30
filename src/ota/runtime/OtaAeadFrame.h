#pragma once

// Structural (non-cryptographic) wire framing for the OTA AEAD transport:
// AD (associated-data) construction, header3 encode/decode, and payload-
// length bounds enforcement -- kept separate from the actual ChaCha20-
// Poly1305 seal/open (OtaAeadCipher.h) so this half is directly native-
// testable without any dependency on the Arduino Crypto library.
//
// Outer frame layout (the `0x0C` OTA-AEAD type tag itself is a Mesh
// custom-data type byte carried outside this "payload", per the transport
// layer's own framing; only the bytes below count towards the 178/179-
// byte payload figures quoted in the coordinator's transport decision):
//
//   Pairwise (form 0xA1): header3 = [0xA1][destHash][srcHash]
//   Group    (form 0xA2): header3 = [0xA2][selectorHi][selectorLo]
//
//   payload = header3(3) || sequenceBE32(4) || ciphertext(N) || tag(16)
//           = 23 + N bytes.
//
// Associated data (authenticated but not encrypted):
//   AD = "MeshCore/OTA/AEAD1" (ASCII, no NUL, 18 bytes)
//     || 0x0C
//     || header3(3)
//     || sequenceBE32(4)
//     || N_BE16(2)
//   = 28 bytes total.
//
// Plaintext length N bounds: the campaign wire header alone is 21 bytes
// (Astra's superseded "17" arithmetic is not authoritative) -- N must be
// AT LEAST 21 (anything shorter cannot even hold a valid campaign header)
// and AT MOST 156 (the coordinator-approved authenticated frame budget;
// 155 is the typical 128-byte-chunk case, 156 is the true ceiling). Any
// N outside [21, 156], any unrecognized form byte, any declared length
// that does not reduce to a whole number of ciphertext+tag bytes, or any
// tag shorter than the full 16 bytes is rejected before any decrypt
// attempt -- see OtaAeadCipher.h for the actual AEAD open, which never
// exposes plaintext to a caller before its own tag check succeeds.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace meshcore {
namespace ota {
namespace runtime {

enum class OtaAeadForm : uint8_t {
  Pairwise = 0xA1,
  Group = 0xA2,
};

// Mesh custom-data type tag this transport is carried under. Lives
// outside the "payload" byte-accounting above (Mesh's own dispatch already
// consumes/re-adds this byte elsewhere); kept here only so callers building
// the AD have a single authoritative constant.
constexpr uint8_t kOtaAeadTypeTag = 0x0C;

constexpr size_t kOtaAeadHeader3Bytes = 3;
constexpr size_t kOtaAeadSequenceBytes = 4;
constexpr size_t kOtaAeadTagBytes = 16;
constexpr size_t kOtaAeadFixedOverheadBytes =
    kOtaAeadHeader3Bytes + kOtaAeadSequenceBytes + kOtaAeadTagBytes;  // 23

constexpr size_t kOtaAeadMinPlaintextBytes = 21;   // the campaign wire header's own size.
constexpr size_t kOtaAeadMaxPlaintextBytes = 156;  // coordinator-approved authenticated frame budget.

constexpr size_t kOtaAeadMinPayloadBytes = kOtaAeadFixedOverheadBytes + kOtaAeadMinPlaintextBytes;  // 44
constexpr size_t kOtaAeadMaxPayloadBytes = kOtaAeadFixedOverheadBytes + kOtaAeadMaxPlaintextBytes;  // 179

struct OtaAeadHeader3Pairwise {
  uint8_t dest_hash = 0;
  uint8_t src_hash = 0;
};

struct OtaAeadHeader3Group {
  uint16_t selector = 0;
};

// Result of a purely-structural parse: the plaintext is NOT yet decrypted
// or authenticated at this point -- `ciphertext`/`tag` point INTO the
// caller-owned wire buffer, unverified. A caller MUST run these through
// OtaAeadCipher::open() (which never surfaces plaintext before its own
// tag check passes) before treating them as real data.
struct OtaAeadParsedFrame {
  bool ok = false;
  OtaAeadForm form = OtaAeadForm::Pairwise;
  OtaAeadHeader3Pairwise pairwise;
  OtaAeadHeader3Group group;
  uint32_t sequence = 0;
  const uint8_t* ciphertext = nullptr;
  size_t ciphertext_len = 0;
  const uint8_t* tag = nullptr;  // exactly kOtaAeadTagBytes.
};

class OtaAeadFrame {
public:
  // Builds the 28-byte associated data. Returns false (nothing written) if
  // `n` is outside [kOtaAeadMinPlaintextBytes, kOtaAeadMaxPlaintextBytes]
  // or `out_cap` is too small.
  static bool buildAssociatedData(const uint8_t header3[kOtaAeadHeader3Bytes], uint32_t sequence, uint16_t n,
                                 uint8_t* out, size_t out_cap, size_t* out_len) {
    static const char kLabel[] = "MeshCore/OTA/AEAD1";
    constexpr size_t kLabelBytes = sizeof(kLabel) - 1;  // no NUL.
    constexpr size_t kTotal = kLabelBytes + 1 + kOtaAeadHeader3Bytes + 4 + 2;
    if (n < kOtaAeadMinPlaintextBytes || n > kOtaAeadMaxPlaintextBytes) return false;
    if (header3 == nullptr || out == nullptr || out_cap < kTotal) return false;

    size_t off = 0;
    memcpy(out + off, kLabel, kLabelBytes);
    off += kLabelBytes;
    out[off++] = kOtaAeadTypeTag;
    memcpy(out + off, header3, kOtaAeadHeader3Bytes);
    off += kOtaAeadHeader3Bytes;
    out[off++] = static_cast<uint8_t>(sequence >> 24);
    out[off++] = static_cast<uint8_t>(sequence >> 16);
    out[off++] = static_cast<uint8_t>(sequence >> 8);
    out[off++] = static_cast<uint8_t>(sequence);
    out[off++] = static_cast<uint8_t>(n >> 8);
    out[off++] = static_cast<uint8_t>(n);
    if (out_len != nullptr) *out_len = off;
    return true;
  }

  static constexpr size_t associatedDataBytes() {
    return (sizeof("MeshCore/OTA/AEAD1") - 1) + 1 + kOtaAeadHeader3Bytes + 4 + 2;  // 28
  }

  // Encodes the pairwise payload header3+seq (NOT the ciphertext/tag,
  // which the caller appends after sealing -- see OtaAeadCipher.h).
  static void encodeHeader3Pairwise(uint8_t dest_hash, uint8_t src_hash, uint8_t out[kOtaAeadHeader3Bytes]) {
    out[0] = static_cast<uint8_t>(OtaAeadForm::Pairwise);
    out[1] = dest_hash;
    out[2] = src_hash;
  }

  static void encodeHeader3Group(uint16_t selector, uint8_t out[kOtaAeadHeader3Bytes]) {
    out[0] = static_cast<uint8_t>(OtaAeadForm::Group);
    out[1] = static_cast<uint8_t>(selector >> 8);
    out[2] = static_cast<uint8_t>(selector);
  }

  static void encodeSequence(uint32_t sequence, uint8_t out[kOtaAeadSequenceBytes]) {
    out[0] = static_cast<uint8_t>(sequence >> 24);
    out[1] = static_cast<uint8_t>(sequence >> 16);
    out[2] = static_cast<uint8_t>(sequence >> 8);
    out[3] = static_cast<uint8_t>(sequence);
  }

  // Purely structural parse of a received payload (header3+seq+ciphertext
  // +tag, i.e. everything after the outer 0x0C type tag has already been
  // stripped by the caller/dispatcher). Rejects: unknown form byte, any
  // payload shorter than the minimum frame, any payload whose implied
  // ciphertext length falls outside [kOtaAeadMinPlaintextBytes,
  // kOtaAeadMaxPlaintextBytes], and (structurally) any frame that could
  // not possibly carry a full 16-byte tag. Does NOT verify the tag itself
  // -- that is exclusively OtaAeadCipher::open()'s job.
  static OtaAeadParsedFrame parse(const uint8_t* payload, size_t payload_len) {
    OtaAeadParsedFrame result;
    if (payload == nullptr || payload_len < kOtaAeadMinPayloadBytes || payload_len > kOtaAeadMaxPayloadBytes) {
      return result;  // ok=false
    }
    const uint8_t form_byte = payload[0];
    const size_t ciphertext_len = payload_len - kOtaAeadFixedOverheadBytes;
    if (ciphertext_len < kOtaAeadMinPlaintextBytes || ciphertext_len > kOtaAeadMaxPlaintextBytes) {
      return result;
    }

    if (form_byte == static_cast<uint8_t>(OtaAeadForm::Pairwise)) {
      result.form = OtaAeadForm::Pairwise;
      result.pairwise.dest_hash = payload[1];
      result.pairwise.src_hash = payload[2];
    } else if (form_byte == static_cast<uint8_t>(OtaAeadForm::Group)) {
      result.form = OtaAeadForm::Group;
      result.group.selector = static_cast<uint16_t>((static_cast<uint16_t>(payload[1]) << 8) | payload[2]);
    } else {
      return result;  // unrecognized form -- reject, no fallback/guess.
    }

    result.sequence = (static_cast<uint32_t>(payload[3]) << 24) | (static_cast<uint32_t>(payload[4]) << 16) |
                      (static_cast<uint32_t>(payload[5]) << 8) | static_cast<uint32_t>(payload[6]);
    result.ciphertext = payload + kOtaAeadHeader3Bytes + kOtaAeadSequenceBytes;
    result.ciphertext_len = ciphertext_len;
    result.tag = result.ciphertext + ciphertext_len;
    result.ok = true;
    return result;
  }
};

}  // namespace runtime
}  // namespace ota
}  // namespace meshcore
