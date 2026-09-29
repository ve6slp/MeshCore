#!/usr/bin/env python3
"""Generate a repo-local lab Ed25519 key and explicitly update the public header."""

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
KEY_DIR = ROOT / ".tmp" / "xiao-ota-keys"
PRIVATE = KEY_DIR / "lab-ed25519-private.pem"
PUBLIC = KEY_DIR / "lab-ed25519-public.pem"
HEADER = ROOT / "bootloader" / "xiao_nrf52840_ota" / "include" / "xiao_ota_public_key.h"

KEY_DIR.mkdir(parents=True, exist_ok=True)
if not PRIVATE.exists():
    subprocess.check_call(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(PRIVATE)])
subprocess.check_call([
    "openssl", "pkey", "-in", str(PRIVATE), "-pubout", "-out", str(PUBLIC)
])
der = subprocess.check_output([
    "openssl", "pkey", "-pubin", "-in", str(PUBLIC), "-outform", "DER"
])
if der[:12].hex() != "302a300506032b6570032100" or len(der) != 44:
    raise SystemExit("unexpected Ed25519 SubjectPublicKeyInfo encoding")
raw = der[-32:]
rows = []
for i in range(0, 32, 8):
    rows.append("    " + ", ".join(f"0x{x:02x}" for x in raw[i:i + 8]) + ",")
HEADER.write_text(
    "#pragma once\n\n#include <stdint.h>\n\n"
    "/* Lab-only public key. The private half is generated under .tmp and is never committed. */\n"
    "static const uint8_t xiao_ota_lab_public_key_ed25519[32] = {\n"
    + "\n".join(rows) + "\n};\n"
)
print(f"private key: {PRIVATE}")
print(f"public key:  {PUBLIC}")
print(f"updated:     {HEADER}")

