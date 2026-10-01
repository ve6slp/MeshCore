#pragma once

// Concrete, board-level implementations of the two narrow seams
// `DeviceAuthorityGuard` (src/ota/authority/DeviceAuthorityGuard.h, NOT
// owned by this scope -- consume-only) needs from real firmware:
// genuine cryptographic entropy for device challenges, and the device's
// own already-loaded Ed25519 identity for signing authority responses.
//
// Deliberately NOT wired into any main.cpp yet: the rest of
// DeviceAuthorityGuard's dependencies (DeviceAuthorityStore,
// DeviceAuthorityMaintenance, AuthorityIssuerTrust, SignatureVerifier)
// belong to the Authority/Store implementation owners, not this scope.
// This header exists so those owners can bind real board entropy/signing
// the moment their side lands, instead of a placeholder/fake-success
// stand-in ever being written here or there.
//
// Arduino-dependent (RadioLib PhysicalLayer, mesh::LocalIdentity's actual
// Ed25519 backend) -- NOT natively testable; verified by careful manual
// inspection against RadioNoiseListener's and LocalIdentity::sign's
// existing, already-used contracts only.

#include <Arduino.h>
#include <RadioLib.h>
#include <Identity.h>
#include <helpers/radiolib/RadioLibWrappers.h>
#include "ota/authority/DeviceAuthorityGuard.h"
#include "ota/runtime/OtaControlSessionRouter.h"

namespace mesh {
namespace ota {
namespace helpers {

// Real per-call radio-noise entropy for device challenges -- the SAME
// entropy quality bar already established for `radio_new_identity()`
// (see variants/xiao_nrf52/target.cpp, variants/sensecap_solar/target.cpp):
// RadioNoiseListener(radio), never millis()/StdRNG/host-supplied bytes.
// `radioAvailableFn` must reflect the SAME "did radio_init() actually
// succeed" fact main.cpp already tracks -- reading radio noise from a
// driver object that exists but was never successfully initialized would
// silently resurrect exactly the "driver pointer exists" readiness bug
// already fixed elsewhere in this firmware. A failed/absent radio
// produces no fresh nonce at all (false), never a degraded fallback.
class OtaDeviceAuthorityRadioEntropy : public mesh::ota::authority::DeviceAuthorityEntropy {
  PhysicalLayer* _radio;
  bool (*_radio_available_fn)();

public:
  OtaDeviceAuthorityRadioEntropy(PhysicalLayer& radio, bool (*radio_available_fn)())
    : _radio(&radio), _radio_available_fn(radio_available_fn) { }

  bool freshNonce(uint8_t out_nonce[mesh::ota::authority::kChallengeBytes]) override {
    if (_radio == nullptr || _radio_available_fn == nullptr || !_radio_available_fn()) return false;
    RadioNoiseListener rng(*_radio);
    rng.random(out_nonce, mesh::ota::authority::kChallengeBytes);
    return true;
  }
};

// Signs with the device's own already-loaded Ed25519 identity
// (LocalIdentity::sign, the SAME private key backing
// `AuthorityBinding::meshFullPublicKey`) -- never derives, regenerates,
// or substitutes a key here. `identityAvailableFn` must reflect the same
// "a real identity was actually loaded/bound" fact main.cpp/MyMesh
// already track (e.g. `_identity_available_`); a device that has not
// genuinely loaded its identity must refuse to sign, never sign with a
// zero/uninitialized/placeholder key.
class OtaDeviceAuthorityIdentitySigner : public mesh::ota::authority::DeviceIdentitySigner {
  const mesh::LocalIdentity* _identity;
  bool (*_identity_available_fn)();

public:
  OtaDeviceAuthorityIdentitySigner(const mesh::LocalIdentity& identity, bool (*identity_available_fn)())
    : _identity(&identity), _identity_available_fn(identity_available_fn) { }

  bool signWithDeviceIdentity(const uint8_t* message, size_t message_len,
                               uint8_t out_signature[mesh::ota::authority::kSignatureBytes]) override {
    static_assert(SIGNATURE_SIZE == mesh::ota::authority::kSignatureBytes,
                  "LocalIdentity::sign()'s signature size must match DeviceAuthorityGuard's kSignatureBytes exactly");
    if (_identity == nullptr || _identity_available_fn == nullptr || !_identity_available_fn()) return false;
    _identity->sign(out_signature, message, (int)message_len);
    return true;
  }
};

// Same real per-call radio-noise entropy, bound instead to the USB
// commissioning router's narrower `IOtaControlEntropySource` seam
// (session ids / CHALLENGE bytes) -- deliberately the SAME quality bar
// and the SAME fail-closed behaviour as `OtaDeviceAuthorityRadioEntropy`
// above: no millis()/StdRNG/host-supplied bytes, and a failed/absent
// radio yields no fresh bytes at all (false) rather than a degraded
// fallback. A single shared `RadioNoiseListener` instance would leak
// state between the two independent entropy consumers, so this is its
// own small adapter rather than one shared across both interfaces.
class OtaControlRadioEntropy : public meshcore::ota::runtime::IOtaControlEntropySource {
  PhysicalLayer* _radio;
  bool (*_radio_available_fn)();

public:
  OtaControlRadioEntropy(PhysicalLayer& radio, bool (*radio_available_fn)())
    : _radio(&radio), _radio_available_fn(radio_available_fn) { }

  bool fillRandom(uint8_t* dest, size_t len) override {
    if (_radio == nullptr || _radio_available_fn == nullptr || !_radio_available_fn()) return false;
    RadioNoiseListener rng(*_radio);
    rng.random(dest, len);
    return true;
  }
};

}  // namespace helpers
}  // namespace ota
}  // namespace mesh
