#!/usr/bin/env python3
"""Generate (or reuse) a private Ed25519 keypair as an OFFLINE TEST FIXTURE
ONLY, under .tmp (never committed), for local/manual signing workflows that
need to pass a --private-key to tools/sign_image.py (e.g. bench packaging
dry runs, manual lab testing).

This tool does NOT read or write any compiled header, does NOT provision or
rotate the boot-info marker's reference_signer_public_key_ed25519 placeholder
(include/xiao_ota_public_key.h, a fixed value committed in source control --
see that header's own comment), and establishes no "default trust" key of
any kind. It makes no claim about what key a real MeshCore admin uses or
what the bootloader will accept on-device: that is always decided per
install command via admitted_signer_public_key_ed25519 (xiao_ota_record.h),
snapshotted by the already-trusted running app at COMMIT time. A real
production app/host never exports a private key to a tool like this at
all -- it signs entirely through the existing companion protocol (host
CMD33 start / CMD34 raw message bytes / CMD35 finish, returning only the
signature), never handing raw private-key material to disk or to this
script.
"""

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
KEY_DIR = ROOT / ".tmp" / "xiao-ota-keys"
PRIVATE = KEY_DIR / "lab-ed25519-private.pem"
PUBLIC = KEY_DIR / "lab-ed25519-public.pem"


def main() -> int:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if not PRIVATE.exists():
        subprocess.check_call(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(PRIVATE)]
        )
    subprocess.check_call(
        ["openssl", "pkey", "-in", str(PRIVATE), "-pubout", "-out", str(PUBLIC)]
    )
    print(f"private key fixture (offline/test only): {PRIVATE}")
    print(f"public key fixture  (offline/test only): {PUBLIC}")
    print(
        "Pass PRIVATE to sign_image.py's --private-key explicitly for local "
        "signing/testing. This script never touches any compiled header and "
        "provisions no runtime trust: production signing uses the existing "
        "host companion protocol (CMD33/34/35), never a private-key export."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
