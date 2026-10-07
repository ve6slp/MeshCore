#pragma once

/*
 * Thin forwarding stub, NOT a copy of the contract itself: the single
 * source of truth for the shared QSPI/internal-flash partitioning
 * constants is src/ota/platform/Nrf52FlashLayoutContract.h (owned by
 * MAIN, never edited here). This indirection exists purely so
 * tools/prepare_upstream.py can, at prepare time, overwrite THIS file
 * (only, inside the disposable upstream build tree) with a verbatim
 * copy of that header's live content -- because a plain relative
 * "../../../src/ota/platform/..." #include, while correct for the
 * native/host build (this file's real, fixed location in the repo),
 * would silently resolve to the WRONG (or a nonexistent) path once
 * xiao_ota_layout.h is copied into the upstream ARM build tree at a
 * different directory depth. See prepare_upstream.py's
 * copy_platform_layout_contract() for the upstream-side replacement;
 * never add a stale/duplicated literal copy of the contract's values
 * here -- this file must always either forward to the real contract
 * (native) or be REPLACED outright with its exact current bytes
 * (upstream prepare), never hand-maintained in between.
 */
#include "../../../src/ota/platform/Nrf52FlashLayoutContract.h"
