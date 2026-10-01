#pragma once

// Adapters binding a verified DeviceAuthorityGuard activation grant to the
// EXISTING one-use commissioning-authority seam already defined in
// ota/runtime/OtaSequenceBackingPort.h (ITxSequenceCommissioningAuthority /
// IRxSequenceCommissioningAuthority). This is the concrete answer to "TX/RX
// adapters get narrowly verified permissions, not generic factory
// boolean": these adapters refuse unless the guard has an ACTUAL,
// cryptographically-verified ActivationSpent grant whose exact floor
// matches what the backing store is asking to commission, and each
// adapter instance permits exactly one real commissioning call ever (a
// second call -- even with an identical, still-valid grant -- is refused,
// since a real backing store's own Missing-only precondition is what
// makes re-commissioning meaningful, not this adapter silently allowing
// repeats).
//
// Wiring a real ITxSequenceBackingStore/IRxSequenceBackingStore instance
// to actually CALL through these adapters (rather than some other
// factory-boolean shortcut) is MAIN's later integration step; this file
// only defines the narrow seam.

#include <cstring>
#include "ota/authority/DeviceAuthorityGuard.h"
#include "ota/runtime/OtaSequenceBackingPort.h"

namespace ota {
namespace authority {

class AuthorityTxCommissioningAdapter : public meshcore::ota::runtime::ITxSequenceCommissioningAuthority {
public:
  explicit AuthorityTxCommissioningAdapter(const DeviceAuthorityGuard& guard) : guard_(guard) {}

  bool commissionVirginTx(uint32_t initialUpperBound) override {
    if (consumed_) return false;
    TxRxActivationGrant grant;
    if (guard_.currentActivationGrant(grant) != AuthorityOutcome::Ok) return false;
    // "Exact permitted root/counters" -- the caller must be asking to
    // commission precisely the floor the authority actually verified,
    // never a smaller/larger value it merely hopes is close enough.
    if (grant.txSequenceFloor == 0 || initialUpperBound != grant.txSequenceFloor) return false;
    consumed_ = true;
    return true;
  }

private:
  const DeviceAuthorityGuard& guard_;
  bool consumed_ = false;
};

class AuthorityRxCommissioningAdapter : public meshcore::ota::runtime::IRxSequenceCommissioningAuthority {
public:
  explicit AuthorityRxCommissioningAdapter(const DeviceAuthorityGuard& guard) : guard_(guard) {}

  bool commissionVirginRx(const meshcore::ota::runtime::OtaRxLedgerContext& context, uint32_t initialWatermark) override {
    (void)context;  // The grant is per-activated-transaction, not per-context; a real multi-context
                     // integration binds context selection at the caller (MAIN's later step).
    if (consumed_) return false;
    TxRxActivationGrant grant;
    if (guard_.currentActivationGrant(grant) != AuthorityOutcome::Ok) return false;
    if (grant.rxReplayFloor == 0 || initialWatermark != grant.rxReplayFloor) return false;
    consumed_ = true;
    return true;
  }

private:
  const DeviceAuthorityGuard& guard_;
  bool consumed_ = false;
};

}  // namespace authority
}  // namespace ota
