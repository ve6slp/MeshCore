#pragma once

// RAM-only, process/boot-local physical-resource identity for this MCU's
// QSPI peripheral + chip-select GPIO pairing.
//
// This is deliberately NOT a board-model label, device UID, or any kind of
// persistent/authorization identity -- it exists purely so that two
// independently-constructed in-process callers (e.g. a board backend's
// media-arbiter guard and a future real `OtaSecurityStore` construction)
// can agree, within ONE running MCU's RAM, that they are genuinely
// contending over the SAME physical QSPI bus wired to the SAME physical
// chip-select line -- not merely sharing an arbitrary board-species
// literal. Each MCU has its own independent RAM registry; there is no
// cross-device meaning and no device-identity/authorization requirement
// here.
//
// Supported MCUs (nRF52840) have exactly ONE `NRF_QSPI` peripheral
// instance, memory-mapped at a single fixed base address
// (`kQspiPeripheralBaseAddress` below, verified against the real SDK
// macro on-target). Combined with the actual absolute Nordic GPIO pin
// number actually wired as chip-select (0..47 on nRF52840: P0.00..P0.31
// and P1.00..P1.15) -- i.e. EXACTLY `g_ADigitalPinMap[PIN_QSPI_CS]`, the
// same value `Nrf52FlashAdapter::begin()` already passes to
// `nrfx_qspi_config_t::pins.csn_pin` to actually drive the hardware --
// this pairing is sufficient to identify "this one real QSPI controller,
// driving this one real CS line": two adapters that would genuinely
// collide on real silicon (same peripheral, same CS pin) always produce
// the identical token, and two adapters wired to genuinely distinct CS
// lines (hence genuinely independent flash parts) always produce
// distinct tokens.

#include <stdint.h>

#if defined(NRF52840_XXAA)
#include <nrf_qspi.h>
#endif

namespace ota {
namespace platform {

// The nRF52840's single QSPI peripheral instance base address.
constexpr uint32_t kQspiPeripheralBaseAddress = 0x40029000u;

#if defined(NRF52840_XXAA) && defined(NRF_QSPI_BASE)
static_assert(kQspiPeripheralBaseAddress == NRF_QSPI_BASE,
              "kQspiPeripheralBaseAddress must match the real NRF_QSPI_BASE "
              "from the Nordic SDK headers actually in use on this target");
#endif

// `actual_nrf_gpio_pin` MUST be the real, absolute Nordic GPIO pin number
// (0..47 on nRF52840) actually wired as this adapter's QSPI chip-select
// line -- exactly `g_ADigitalPinMap[PIN_QSPI_CS]`, never a raw Arduino
// digital-pin index or any other board-species label. Any value outside
// [0,47] is not a real absolute GPIO pin number on this MCU and is
// rejected as token 0 (the same "Unavailable" convention used elsewhere
// in this codebase for a genuine configuration gap), never silently
// accepted or wrapped.
constexpr uint64_t tokenForChipSelectPin(uint32_t actual_nrf_gpio_pin) {
  return (actual_nrf_gpio_pin > 47u)
             ? 0u
             : ((static_cast<uint64_t>(kQspiPeripheralBaseAddress) << 32) |
                (static_cast<uint64_t>(actual_nrf_gpio_pin) + 1u));
}

}  // namespace platform
}  // namespace ota
