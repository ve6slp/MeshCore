#!/usr/bin/env python3
"""Synthetic test identity only; production Python encoder -> real C++ receiver."""
import hashlib
import lzma
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import ota_compression as codec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def generate(output, image_path=None):
    image = (Path(image_path).read_bytes() if image_path else
             hashlib.shake_256(b"clearly synthetic incompressible block").digest(codec.GROUP) +
             (bytes(range(256)) + b"\x00\xf0\x00\xf8") * 63 + b"tail" * 5)
    canonical = (bytes.fromhex("1001000207") + struct.pack(">II", 0x27000, len(image)) +
                 hashlib.sha256(image).digest() + struct.pack(">IIHHH", 5, 3, 1, 1, 1))
    digest = hashlib.sha256(canonical).digest()
    target = bytes(range(0xD0, 0xF0))
    # Published, synthetic fixture seed, NEVER a device or trust key.
    key = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    owner = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    nonce = hashlib.sha256(b"MeshCore/OTA/begin-nonce/v1" + bytes([0x42]) * 32 + digest).digest()[:16]
    frames = [b"\x08" + hashlib.sha256(target).digest()[:8] + owner + canonical + key.sign(canonical)]
    for group in codec.groups(image, arm_thumb=True):
        for prefix in group.fragments(digest, codec.fragment_capacity(1, 1, True)):
            frames.append(prefix + key.sign(codec.signed_message(target, digest, 1, nonce, prefix)))
    packed = (b"OCF1" + canonical + owner + target + nonce + struct.pack(">I", len(image)) + image +
              struct.pack(">I", len(frames)) +
              b"".join(struct.pack(">H", len(frame)) + frame for frame in frames))
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(packed)
    vectors = []
    for name, raw in (("a", b"A"), ("aa", b"AA")):
        encoded = lzma.compress(raw, format=lzma.FORMAT_RAW, filters=codec.filters(False))
        vectors.append("static const unsigned char vector_" + name + "[]={" +
                       ",".join(str(b) for b in encoded) + "};")
    output.with_name("decoder_vectors.h").write_text("\n".join(vectors) + "\n")
    print(f"production encoder fixture: {len(image)} raw bytes, {len(frames)-1} signed compressed fragments")


if __name__ == "__main__":
    generate(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
