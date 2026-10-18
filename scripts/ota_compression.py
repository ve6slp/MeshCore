"""Immutable OTA v4 packages and independent bounded LZMA1 chunks."""
from dataclasses import dataclass
import hashlib
import importlib.util
import lzma
from pathlib import Path
import struct

from ota_common import CHUNK_BYTES, MAX_CHUNKS, MAX_MANIFEST, Error, domain, verify

PREFIX_BYTES = 163
ENTRY_BYTES = 35
MANIFEST_BASE = PREFIX_BYTES + 64
RAW, LZMA, LZMA_THUMB = 0, 1, 2


def filters(thumb=False, offset=0):
    prefix = [{"id": lzma.FILTER_ARMTHUMB, "start_offset": offset}] if thumb else []
    return prefix + [{"id": lzma.FILTER_LZMA1, "dict_size": 8192, "lc": 0, "lp": 1, "pb": 1,
                     "mode": lzma.MODE_NORMAL, "mf": lzma.MF_BT4, "nice_len": 273, "depth": 1000}]


def descriptor(image, board, role, counter):
    path = Path(__file__).resolve().parents[1] / "bootloader/xiao_nrf52840_ota/tools/xiao_ota_descriptor.py"
    spec = importlib.util.spec_from_file_location("ota_boot_descriptor", path)
    codec = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(codec)
    codec.assert_matches_canonical_layout_contract()
    return codec.build_descriptor(board, role, counter, image)


def validate_descriptor(canonical, image):
    if (len(canonical) != 59 or not 0 < len(image) <= CHUNK_BYTES * MAX_CHUNKS
            or struct.unpack_from(">I", canonical, 9)[0] != len(image)
            or canonical[13:45] != hashlib.sha256(image).digest()
            or canonical[4] not in (0, 1) or canonical[53:59] != struct.pack(">HHH", 1, 1, 1)):
        raise Error("canonical59 geometry/hash/policy mismatch")


@dataclass(frozen=True)
class Chunk:
    codec: int
    stored: bytes
    raw_hash: bytes


@dataclass(frozen=True)
class Package:
    manifest: bytes
    chunks: tuple
    canonical: bytes
    owner: bytes
    raw: bytes

    @property
    def digest(self):
        return hashlib.sha256(self.manifest).digest()

    @property
    def tag(self):
        return self.digest[:8]

    @property
    def raw_hash(self):
        return self.canonical[13:45]

    @property
    def counter(self):
        return struct.unpack_from(">I", self.canonical, 45)[0]

    def encode(self):
        return self.manifest + b"".join(c.stored for c in self.chunks)

    @classmethod
    def build(cls, image, canonical, owner, signer, compress=True):
        validate_descriptor(canonical, image)
        if len(owner) != 32 or not any(owner):
            raise ValueError("nonzero package signer required")
        thumb = canonical[:4] in (b"XN40", b"SCP1")
        chunks = []
        for offset in range(0, len(image), CHUNK_BYTES):
            raw = image[offset:offset + CHUNK_BYTES]
            choices = [(raw, RAW)]
            if compress:
                choices.append((lzma.compress(raw, format=lzma.FORMAT_RAW,
                                              filters=filters(False)), LZMA))
                if thumb:
                    choices.append((lzma.compress(raw, format=lzma.FORMAT_RAW,
                                                  filters=filters(True)), LZMA_THUMB))
            stored, codec = min(choices, key=lambda item: (len(item[0]), item[1]))
            chunks.append(Chunk(codec, stored, hashlib.sha256(raw).digest()))
        boot_signature = signer(canonical)
        verify(owner, canonical, boot_signature)
        unsigned = (b"MCO4\x04\x0d" + struct.pack(">H", len(chunks)) + owner + canonical
                    + boot_signature + b"".join(
                        bytes([c.codec]) + struct.pack(">H", len(c.stored)) + c.raw_hash for c in chunks))
        signature = signer(domain("package") + unsigned)
        verify(owner, domain("package") + unsigned, signature)
        return cls.decode(unsigned + signature + b"".join(c.stored for c in chunks))

    @classmethod
    def decode(cls, capsule):
        capsule = bytes(capsule)
        if len(capsule) < MANIFEST_BASE or capsule[:6] != b"MCO4\x04\x0d":
            raise Error("not an OTA v4 package")
        count = struct.unpack_from(">H", capsule, 6)[0]
        length = MANIFEST_BASE + ENTRY_BYTES * count
        if not 1 <= count <= MAX_CHUNKS or length > MAX_MANIFEST or len(capsule) < length:
            raise Error("invalid manifest bounds")
        manifest, owner, canonical = capsule[:length], capsule[8:40], capsule[40:99]
        if not any(owner):
            raise Error("zero package signer")
        verify(owner, canonical, capsule[99:163])
        verify(owner, domain("package") + manifest[:-64], manifest[-64:])
        raw_size = struct.unpack_from(">I", canonical, 9)[0]
        if not 0 < raw_size <= CHUNK_BYTES * MAX_CHUNKS or count != (raw_size + 8191) // 8192:
            raise Error("canonical image/chunk count mismatch")
        chunks, decoded, cursor = [], [], length
        for index in range(count):
            at = PREFIX_BYTES + index * ENTRY_BYTES
            codec, stored_size = struct.unpack_from(">BH", manifest, at)
            expected_size = min(CHUNK_BYTES, raw_size - index * CHUNK_BYTES)
            if codec not in (RAW, LZMA, LZMA_THUMB) or not 1 <= stored_size <= expected_size:
                raise Error("invalid chunk codec/length")
            if codec == LZMA_THUMB and canonical[:4] not in (b"XN40", b"SCP1"):
                raise Error("Thumb codec requires an explicitly supported signed board")
            stored = capsule[cursor:cursor + stored_size]
            cursor += stored_size
            if len(stored) != stored_size:
                raise Error("truncated package chunk")
            if codec == RAW:
                raw = stored
            else:
                decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                              filters=filters(codec == LZMA_THUMB))
                try:
                    raw = decoder.decompress(stored, max_length=expected_size + 1)
                except lzma.LZMAError as exc:
                    raise Error("invalid LZMA chunk") from exc
                if not decoder.eof or decoder.unused_data:
                    raise Error("chunk lacks end marker, exceeds bound or has trailing bytes")
            digest = manifest[at + 3:at + 35]
            if len(raw) != expected_size or hashlib.sha256(raw).digest() != digest:
                raise Error("raw chunk SHA-256 mismatch")
            chunks.append(Chunk(codec, stored, digest))
            decoded.append(raw)
        if cursor != len(capsule):
            raise Error("trailing package bytes")
        image = b"".join(decoded)
        validate_descriptor(canonical, image)
        return cls(manifest, tuple(chunks), canonical, owner, image)

    @classmethod
    def open(cls, path):
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_MANIFEST + CHUNK_BYTES * MAX_CHUNKS + 1)
        return cls.decode(data)
