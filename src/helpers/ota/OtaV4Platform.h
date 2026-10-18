#pragma once

#include "OtaV4Protocol.h"

namespace mesh { namespace ota { namespace v4 {

struct Policy {
  uint16_t boardFamily = 0, boardVariant = 0;
  uint8_t role = 0;
  uint32_t appAddress = 0, maxImageBytes = 0, bootloaderCapabilities = 0;
  uint16_t formatId = 1, keyId = 1, algorithmId = 1;
};

struct RunningEvidence {
  uint32_t floor = 0;
  uint8_t hash[kHashBytes] = {};
  uint8_t flags = 0;
};

struct Journal {
  Phase phase = Phase::Idle;
  Result lastResult = Result::Ok;
  uint32_t generation = 0;
  uint16_t nextChunk = 0;
  uint8_t packageHash[kHashBytes] = {};
  uint8_t transaction[kNonceBytes] = {};
};

// Implementations must return failures, never silently substitute evidence,
// entropy, successful writes or cryptography. Only save/repair own the journal;
// boot commands and confirmed-floor/personality stores remain separate.
class Platform {
public:
  virtual ~Platform() = default;
  virtual Policy policy() const = 0;
  virtual Result identity(uint8_t out[32]) = 0;
  virtual Result evidence(RunningEvidence& out) = 0;
  virtual Result random(uint8_t* out, size_t size) = 0;
  virtual bool isCurrentAdmin(const uint8_t key[32]) = 0;
  // domainSize includes the trailing NUL. nullptr/0 means raw canonical59.
  virtual bool verify(const uint8_t key[32], const char* domain, size_t domainSize,
                      const uint8_t* message, size_t messageSize,
                      const uint8_t signature[64]) = 0;
  virtual Result sign(const char* domain, size_t domainSize, const uint8_t* message,
                      size_t messageSize, uint8_t signature[64]) = 0;

  // State means pristine/uninitialized, not corrupt. Any malformed/ambiguous
  // durable record returns Integrity. save is atomic, read-back verified and
  // commits a replacement before retiring the previous record.
  virtual Result recover(Journal& out, uint8_t* manifest, size_t capacity,
                         size_t& manifestSize) = 0;
  virtual Result save(const Journal& journal, const uint8_t* manifest,
                      size_t manifestSize) = 0;
  virtual Result beginStaging(uint32_t rawSize) = 0;
  virtual Result writeStaging(uint32_t offset, const uint8_t* data, size_t size) = 0;
  virtual Result readStaging(uint32_t offset, uint8_t* data, size_t size) = 0;
  virtual Result clearStaging() = 0;
  // Explicit administrator repair; refuses live install/trial and touches only
  // OTA staging and its journal, never identity, preferences or confirmed floor.
  virtual Result repair(const Journal& idle) = 0;

  // Recheck the complete raw hash and genuine descriptor signature at the
  // installation boundary. activate is durable/idempotent for nonce+generation.
  virtual Result validateInstall(const uint8_t canonical[59], const uint8_t signature[64],
                                 const uint8_t signer[32]) = 0;
  virtual Result activate(const uint8_t canonical[59], const uint8_t signature[64],
                          const uint8_t signer[32], const uint8_t transaction[16],
                          uint32_t generation) = 0;
  // State = no lifecycle event; otherwise only Trial, Confirmed or Failed.
  // Events must bind the latest successfully saved/recovered journal's nonce,
  // generation and manifest. Unrelated previous boot outcomes return State.
  virtual Result lifecycle(Phase& phase) = 0;
  // Owns expiry/restoration, cannot mutate ordinary radio preferences.
  virtual Result lease(uint32_t frequencyKHz, uint32_t bandwidthHz, uint8_t sf,
                       uint8_t cr, uint32_t durationMs) = 0;
};

}}}
