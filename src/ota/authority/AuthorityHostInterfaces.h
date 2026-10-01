#pragma once

// Pluggable HOST-side dependencies for AuthorityCoordinator. There are
// deliberately no production-shaped default implementations anywhere in
// this header: a coordinator constructed without every one of these wired
// explicitly denies every operation (see AuthorityCoordinator::missingDependencies).

#include <stdint.h>
#include "ota/authority/AuthorityTypes.h"

namespace ota {
namespace authority {

// Maps an issuer key id (carried, unsigned, in the transaction record) to
// the actual trusted public key material. Kept separate from the
// transaction itself and from any firmware/controller signer so issuer
// trust is an explicit, independently-configured relationship -- never
// implied by "whoever signed the firmware" or "whoever is USB-attached
// right now" (see rule 4 of the approved contract).
class AuthorityIssuerTrust {
public:
  virtual ~AuthorityIssuerTrust() = default;

  // Returns false (deny) if `issuerKeyId` is not a key this deployment
  // explicitly trusts for authority transactions.
  virtual bool lookupIssuerPublicKey(uint16_t issuerKeyId, uint8_t out_public_key[kPublicKeyBytes]) const = 0;
};

// Genuine entropy for the fresh, unpredictable per-session challenge the
// host embeds into every permit. A production implementation must be
// backed by a real CSPRNG; there is no compile-time "zeros" or counter-
// based fallback anywhere in this module.
class AuthorityChallengeProvider {
public:
  virtual ~AuthorityChallengeProvider() = default;
  virtual bool freshChallenge(uint8_t out_challenge[kChallengeBytes]) = 0;
};

}  // namespace authority
}  // namespace ota
