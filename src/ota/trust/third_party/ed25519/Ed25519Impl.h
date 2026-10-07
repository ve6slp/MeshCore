#pragma once

// Header-only inclusion wrapper around the vendored, verify-only Ed25519
// sources (see NOTICE.txt) so they can be consumed by PlatformIO's native
// unit tests without any change to the top-level build configuration
// (build_src_filter for env:native does not include arbitrary new src/
// translation units).
//
// Every translation unit that includes this header gets its own private
// copy of these routines, because the whole block is wrapped in an
// anonymous namespace: anonymous-namespace entities have internal linkage,
// so defining `ed25519_verify` et al. once per including .cpp file does not
// violate the One Definition Rule even though several different test
// binaries (or, in principle, several .cpp files within the same binary)
// include this same header.
//
// sign.c / keypair.c are included alongside verify.c so that test code can
// perform genuine Ed25519 sign/verify round trips (constructing real signed
// descriptors to exercise DescriptorVerifier). Production firmware code in
// this subsystem (Ed25519SignatureVerifier, DescriptorVerifier) only ever
// calls ed25519_verify -- signing is inherently a build/release-time
// operation, not something a device does to itself.

namespace ota {
namespace trust {
namespace ed25519_impl {

namespace {

#include "fixedint.h"
#include "fe.h"
#include "fe.c"
#include "sc.h"
// fe.c and sc.c each independently define their own file-private `static
// uint64_t load_3(...)`/`load_4(...)` helpers. Upstream, these never
// collide because fe.c and sc.c are compiled as separate translation
// units. Here they are textually concatenated into a single translation
// unit (that is the whole point of this header-only wrapper), so without
// disambiguation the second definition would be an ODR violation within
// this one TU. Rename sc.c's private copies only; they are file-local
// helpers with no external declaration anywhere, so this is purely
// cosmetic and does not change behavior.
#define load_3 sc_impl_load_3
#define load_4 sc_impl_load_4
#include "sc.c"
#undef load_3
#undef load_4
#include "ge.h"
#include "ge.c"
#include "sha512.h"
#include "sha512.c"
#include "ed25519.h"
#include "verify.c"
#include "keypair.c"
#include "sign.c"

}  // namespace

}  // namespace ed25519_impl
}  // namespace trust
}  // namespace ota
