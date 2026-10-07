#pragma once

// Trust/staging interfaces consumed (not implemented) by this OTA runtime.
//
// This module performs NO cryptography and NO flash/storage writes. An
// integrator supplies concrete implementations backed by whatever
// crypto library/HSM and storage/staging area (QSPI, A/B partition, etc.)
// is appropriate for the target. If no implementation is attached, every
// trust/staging decision fails closed.

#include <cstdint>
#include <cstddef>
#include "../protocol/OtaDescriptor.h"
#include "../protocol/OtaMessages.h"
#include "OtaSessionIdentity.h"

namespace meshcore {
namespace ota {
namespace runtime {

class IOtaTrustProvider {
public:
  virtual ~IOtaTrustProvider() = default;

  // canonicalDescriptor/descriptorLen: bytes produced by
  // encodeOtaDescriptorCanonical(). signature/signatureLen: opaque signature
  // blob understood by the concrete implementation, per (keyId, algorithmId).
  virtual bool verifyDescriptorSignature(const uint8_t* canonicalDescriptor, size_t descriptorLen,
                                          const uint8_t* signature, size_t signatureLen,
                                          uint16_t keyId, uint16_t algorithmId) = 0;

  // Verifies the complete signed descriptor metadata using the production
  // trust pipeline. The default preserves fail-closed behavior for older
  // providers that only implement the legacy signature hook.
  virtual bool verifyDescriptor(const protocol::OtaDescriptor&,
                                const uint8_t* signature, size_t signatureLen) {
    (void)signature;
    (void)signatureLen;
    return false;
  }

  // Full descriptor policy check: target/role/address binding, bootloader
  // capability and anti-rollback counter. Production implementations should
  // delegate to ota::trust::DescriptorVerifier::verifyDescriptor(); the
  // default remains fail-closed for tests/integrations that only provide the
  // legacy signature hook.
  virtual bool verifyDescriptorPolicy(const protocol::OtaDescriptor&) { return false; }

  // Policy-only check for lean OTA admission: validates target/role/address/
  // capabilities/counter without assuming any particular signer identity.
  virtual bool verifyDescriptorPolicyOnly(const protocol::OtaDescriptor& descriptor) {
    return verifyDescriptorPolicy(descriptor);
  }

  // Receiver-local authorization gate. This must be a real local decision
  // derived from a previously verified descriptor and a decoded
  // Authorization payload, not merely the presence of an Authorization frame.
  virtual bool authorizeTransfer(const protocol::OtaDescriptor&,
                                  const protocol::OtaAuthorizationPayload&) { return false; }

  // Recompute/verify the staged candidate image hash against the descriptor.
  // Production implementations should delegate to the trust image-hash
  // pipeline over the staging flash region.
  virtual bool verifyStagedImageHash(const protocol::OtaDescriptor&) { return false; }

  // Lean-path counterpart of verifyStagedImageHash(): recomputes/verifies
  // the staged candidate's image bytes against the descriptor's embedded
  // sha256, WITHOUT requiring the legacy compiled-anchor
  // verifyDescriptor()/descriptor_verified_ state (the lean admission path
  // only ever calls verifyDescriptorPolicyOnly() -- a full legacy
  // verifyDescriptor() never runs, so a verifyStagedImageHash() that
  // gates on that flag would fail closed for every lean candidate, not
  // merely a hostile one). The default remains fail-closed for providers
  // that only implement the legacy hook.
  virtual bool verifyStagedImageHashPolicyOnly(const protocol::OtaDescriptor&) { return false; }

  // Durably commit the anti-rollback floor after a verified image has been
  // accepted for install. Production implementations should delegate to the
  // monotonic counter backend via ota::trust::DescriptorVerifier.
  virtual bool commitSecurityCounter(uint32_t) { return false; }

  // The only genuinely cryptographically-verified identity anywhere in
  // this transport: the Ed25519 public key that verified the descriptor's
  // signature (see verifyDescriptorSignature()/verifyDescriptor() above).
  // Returns true and fills `out[32]` iff a descriptor has actually been
  // verified against a known key; returns false (leaving `out` untouched)
  // otherwise -- callers must treat false as "no controller identity is
  // available yet", never silently substitute an all-zero/placeholder key.
  virtual bool controllerIdentity(uint8_t out[32]) {
    (void)out;
    return false;
  }
};

class IOtaStagingSink {
public:
  enum class Result : uint8_t { Ok = 0, Rejected = 1, IoError = 2 };

  virtual ~IOtaStagingSink() = default;

  virtual Result beginSession(const protocol::OtaDescriptor& descriptor) = 0;
  virtual Result resumeSession(const protocol::OtaDescriptor& descriptor) {
    (void)descriptor;
    return Result::Rejected;
  }
  virtual Result writeChunk(uint64_t offset, const uint8_t* data, size_t len) = 0;
  virtual Result commit() = 0;
  virtual void abort() = 0;

  // Optional read-back of previously-written staged bytes. Needed ONLY by
  // an autonomous RF uploader re-transmitting blocks of a candidate it
  // itself owns (it re-signs each block fresh at TX time with its own
  // identity -- see OtaRfUploader.h -- rather than persisting a
  // pre-computed per-block signature from USB upload time). Default
  // Rejected keeps this additive: sinks that never act as an uploader
  // (e.g. a pure RF-only receiver with no local USB cache) need not
  // implement it, and a sink that lacks a real backing store for
  // read-back fails closed rather than returning fabricated bytes.
  virtual Result readChunk(uint64_t /*offset*/, uint8_t* /*out*/, size_t /*len*/) { return Result::Rejected; }

  // Optional hook: called once, right after the transport's canonical
  // wire descriptor + Ed25519 signature are authenticated (the same event
  // that flips descriptor_verified_ true), with the EXACT verified bytes
  // -- never re-derived or re-signed. Sinks that can durably hand a
  // signed install command to a custom bootloader (see
  // IOtaInstallCommandProviderV2 in OtaFirmwareBackend.h) use this to
  // capture the bytes they need to embed verbatim at commit() time.
  // Default no-op keeps this additive for sinks that don't need it.
  virtual void onVerifiedWireDescriptor(const uint8_t* /*wireDescriptor59*/, size_t /*wireDescriptorLen*/,
                                        const uint8_t* /*signature64*/, size_t /*signatureLen*/) {}

  // Optional hook: called once, right after a locally-authorized
  // Authorization payload is accepted for the given (campaignId,
  // sessionId, attemptId), with the controller identity that verified the
  // descriptor's signature (see IOtaTrustProvider::controllerIdentity()).
  // Sinks that durably bind an install-command transaction identity to
  // "this specific authenticated authorized attempt" (see
  // IOtaInstallCommandProviderV2 in OtaFirmwareBackend.h) use this to
  // capture the session+controller they need at commit() time. Default
  // no-op keeps this additive for sinks that don't need it.
  virtual void onAuthorizedSession(const OtaSessionId& /*session*/,
                                   const uint8_t /*controller*/[32]) {}

  virtual void onAdmittedOwnerIdentity(const uint8_t /*ownerPublicKey*/[32]) {}
};


// Fail-closed helpers: return the "denied"/"rejected" outcome whenever the
// provider/sink pointer is null, so call sites never need a separate
// null-check before every trust decision.
inline bool verifyDescriptorSignatureFailClosed(IOtaTrustProvider* provider,
                                                 const uint8_t* canonicalDescriptor, size_t descriptorLen,
                                                 const uint8_t* signature, size_t signatureLen,
                                                 uint16_t keyId, uint16_t algorithmId) {
  if (provider == nullptr) return false;
  return provider->verifyDescriptorSignature(canonicalDescriptor, descriptorLen, signature, signatureLen, keyId, algorithmId);
}

inline bool verifyDescriptorFailClosed(IOtaTrustProvider* provider, const protocol::OtaDescriptor& descriptor,
                                       const uint8_t* signature, size_t signatureLen) {
  if (provider == nullptr) return false;
  return provider->verifyDescriptor(descriptor, signature, signatureLen);
}

inline bool verifyDescriptorPolicyFailClosed(IOtaTrustProvider* provider, const protocol::OtaDescriptor& descriptor) {
  if (provider == nullptr) return false;
  return provider->verifyDescriptorPolicy(descriptor);
}

inline bool authorizeTransferFailClosed(IOtaTrustProvider* provider, const protocol::OtaDescriptor& descriptor,
                                         const protocol::OtaAuthorizationPayload& authorization) {
  if (provider == nullptr) return false;
  return provider->authorizeTransfer(descriptor, authorization);
}

inline bool verifyStagedImageHashFailClosed(IOtaTrustProvider* provider, const protocol::OtaDescriptor& descriptor) {
  if (provider == nullptr) return false;
  return provider->verifyStagedImageHash(descriptor);
}

inline bool commitSecurityCounterFailClosed(IOtaTrustProvider* provider, uint32_t counter) {
  if (provider == nullptr) return false;
  return provider->commitSecurityCounter(counter);
}

inline IOtaStagingSink::Result stagingBeginFailClosed(IOtaStagingSink* sink, const protocol::OtaDescriptor& descriptor) {
  if (sink == nullptr) return IOtaStagingSink::Result::Rejected;
  return sink->beginSession(descriptor);
}

inline IOtaStagingSink::Result stagingWriteFailClosed(IOtaStagingSink* sink, uint64_t offset,
                                                       const uint8_t* data, size_t len) {
  if (sink == nullptr) return IOtaStagingSink::Result::Rejected;
  return sink->writeChunk(offset, data, len);
}

inline IOtaStagingSink::Result stagingCommitFailClosed(IOtaStagingSink* sink) {
  if (sink == nullptr) return IOtaStagingSink::Result::Rejected;
  return sink->commit();
}

inline void stagingAbortFailClosed(IOtaStagingSink* sink) {
  if (sink != nullptr) sink->abort();
}

} // namespace runtime
} // namespace ota
} // namespace meshcore
