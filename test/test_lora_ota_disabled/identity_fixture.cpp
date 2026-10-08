#include <Identity.h>

// Routing fixtures use real identity/path matching, but never exercise crypto.
namespace mesh {
Identity::Identity() { memset(pub_key, 0, sizeof(pub_key)); }
LocalIdentity::LocalIdentity() : Identity() {}
bool Identity::verify(const uint8_t*, const uint8_t*, int) const { return false; }
void LocalIdentity::sign(uint8_t* sig, const uint8_t*, int) const { memset(sig, 0, SIGNATURE_SIZE); }
void LocalIdentity::calcSharedSecret(uint8_t* secret, const uint8_t*) const { memset(secret, 0, PUB_KEY_SIZE); }
}
