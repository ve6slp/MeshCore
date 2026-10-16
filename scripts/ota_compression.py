"""Shared bounded LZMA1 planner/framing for stock and native host streaming.

No serial/device access. Receiver candidates and canonical manifests remain raw.
"""
from dataclasses import dataclass
import hashlib
import math
import lzma
import struct
import zlib

GROUP = 8064
RAW_BLOCK = 84
POLL = 0x13
REPORT = 0x14
FRAGMENT = 0x15
LZMA = 0xA0
LZMA_THUMB = 0xA1
RAW = 0
HEADER = 18
SIGNATURE = 64
DOMAIN = b"MeshCore/OTA/lzma1/v1"


def manifest_thumb(canonical):
    """Only explicit signed nRF board IDs, never image-byte heuristics."""
    return canonical[:4] in (b"XN40", b"SCP1")


def filters(arm_thumb, offset=0):
    result = [{"id": lzma.FILTER_ARMTHUMB, "start_offset": offset}] if arm_thumb else []
    return result + [{"id": lzma.FILTER_LZMA1, "dict_size": 8192, "lc": 0, "lp": 1, "pb": 1,
                      "mode": lzma.MODE_NORMAL, "mf": lzma.MF_BT4, "nice_len": 273, "depth": 1000}]


def fragment_capacity(width, hops, retry, transport_codes=False):
    if (type(width) is not int or type(hops) is not int or width not in (1, 2, 3)
            or not 0 <= hops <= 63 or width * hops > 64):
        raise ValueError("invalid maximum path width/hops")
    overhead = max(2, 3) + 2 + width * hops + 4 * bool(transport_codes) + 5 * bool(retry) + HEADER + SIGNATURE
    return max(0, 176 - overhead)


@dataclass(frozen=True)
class Group:
    index: int
    raw_bytes: int
    stored: bytes
    profile: int
    crc32: int

    def prefix(self, manifest_hash, offset, capacity):
        if len(manifest_hash) != 32 or not 0 <= offset < len(self.stored) or not 1 <= capacity <= 89:
            raise ValueError("invalid fragment bounds")
        data = self.stored[offset:offset + capacity]
        header = (bytes([FRAGMENT]) + manifest_hash[:4] +
                  struct.pack(">HHHIBH", self.index, len(self.stored), self.raw_bytes,
                              self.crc32, self.profile, offset))
        assert len(header) == HEADER
        return header + data

    def fragments(self, manifest_hash, capacity):
        return tuple(self.prefix(manifest_hash, offset, capacity) for offset in range(0, len(self.stored), capacity))


def signed_message(target, manifest_hash, generation, nonce, prefix):
    if (len(target) != 32 or len(manifest_hash) != 32 or not 0 <= generation <= 0xFFFFFFFF
            or len(nonce) != 16 or not any(nonce) or prefix[:1] != bytes([FRAGMENT])
            or not HEADER < len(prefix) <= HEADER + 89):
        raise ValueError("unbound compressed fragment")
    return DOMAIN + target + manifest_hash + struct.pack(">I", generation) + nonce + prefix


def poll(target, manifest_hash, generation, nonce, group):
    if len(target) != 32 or len(manifest_hash) != 32 or len(nonce) != 16 or not any(nonce):
        raise ValueError("unbound compression progress query")
    return bytes([POLL]) + target + manifest_hash + struct.pack(">I", generation) + nonce + struct.pack(">H", group)


def report(frame, target, manifest_hash, generation, nonce, group, stored_size, arm_thumb=False):
    expected = bytes([REPORT]) + target + manifest_hash + struct.pack(">I", generation) + nonce + struct.pack(">H", group)
    if (len(frame) != 95 or frame[:87] != expected or frame[89] not in (0, 1)
            or frame[90] not in ((LZMA_THUMB,) if arm_thumb else (LZMA, LZMA_THUMB))
            or frame[91:93] != struct.pack(">H", GROUP)):
        raise ValueError("compression capability/progress target/manifest/attempt/profile mismatch")
    offset = struct.unpack_from(">H", frame, 87)[0]
    if offset > stored_size:
        raise ValueError("compression progress outside encoded group")
    if frame[93]:
        raise ValueError(f"receiver LZMA1 error {frame[93]}; never raw-fallback on decode failure")
    if frame[94]:
        raise ValueError(f"receiver compressed-group write error {frame[94]}; durable raw progress retained")
    return offset, bool(frame[89])


def groups(image, *, arm_thumb=False):
    result = []
    for index, at in enumerate(range(0, len(image), GROUP)):
        raw = image[at:at + GROUP]
        packed = lzma.compress(raw, format=lzma.FORMAT_RAW, filters=filters(arm_thumb, at))
        profile = LZMA_THUMB if arm_thumb else LZMA
        if len(packed) >= len(raw):
            packed, profile = raw, RAW
        result.append(Group(index, len(raw), packed, profile, zlib.crc32(raw)))
    return tuple(result)


def physical_airtime(size, bw=62500, sf=7, cr=5):
    symbol = (1 << sf) / bw
    de = int(symbol >= .016)
    symbols = 8 + max(0, math.ceil((8 * size - 4 * sf + 28 + 16) / (4 * (sf - 2 * de)))) * cr
    return ((32 if sf <= 8 else 16) + 4.25 + symbols) * symbol


def plan(image, *, width=1, hops=1, retry=True, recipients=1, bw=62500, sf=7, cr=5, arm_thumb=False):
    if not image or not 1 <= recipients <= 32:
        raise ValueError("nonempty image and 1..32 recipients required")
    encoded = groups(image, arm_thumb=arm_thumb)
    capacity = fragment_capacity(width, hops, retry)
    if not capacity:
        raise ValueError("route leaves no compressed payload capacity")
    path = width * hops
    wire = lambda inner: inner + 2 + path + 5 * bool(retry)
    # No padding: final fragment is variable length. Every packet is signed.
    compressed_sizes = [wire(HEADER + min(capacity, len(g.stored) - at) + SIGNATURE)
                        for g in encoded for at in range(0, len(g.stored), capacity)]
    raw_sizes = [wire(7 + min(RAW_BLOCK, len(image) - at) + SIGNATURE)
                 for at in range(0, len(image), RAW_BLOCK)]
    air = lambda sizes: sum(physical_airtime(n, bw, sf, cr) for n in sizes)
    raw_packets, compressed_packets = len(raw_sizes), len(compressed_sizes) * recipients
    raw_air, compressed_air = air(raw_sizes), air(compressed_sizes) * recipients
    # Both strategies checkpoint after <=4 data packets. Compressed mode adds a
    # fresh initial group query and a raw census checkpoint per group/recipient.
    compressed_polls = sum(1 + math.ceil(math.ceil(len(g.stored) / capacity) / 4) for g in encoded) * recipients
    raw_polls = math.ceil(raw_packets / 4) * recipients
    compressed_control_air = compressed_polls * air([wire(87), wire(95)]) + len(encoded) * recipients * air([wire(67), wire(123)])
    raw_control_air = raw_polls * air([wire(67), wire(123)])
    wins = (compressed_packets < raw_packets and
            compressed_air + compressed_control_air < raw_air + raw_control_air)
    result = {
        "selected": "lzma" if wins else "raw",
        "reason": "fewer signed RF data packets and estimated checkpoint-inclusive airtime" if wins else
                  "compression does not beat existing RAW packet/air model; RAW explicitly selected",
        "image_bytes": len(image), "image_sha256": hashlib.sha256(image).hexdigest(),
        "block_bytes": GROUP, "dictionary_bytes": 8192, "lc": 0, "lp": 1, "pb": 1,
        "arm_thumb": arm_thumb, "capacity": capacity, "path_width": width,
        "max_relay_hops": hops, "retry": retry, "recipient_bound_streams": recipients,
        "admission_max_usb_rx_bytes": 164 + 2 + path + 5 * bool(retry) + 3,
        "legacy_control_path_supported": 164 + 2 + path + 5 * bool(retry) + 3 <= 176,
        "groups": len(encoded), "raw_fallback_groups": sum(g.profile == RAW for g in encoded),
        "stored_bytes": sum(len(g.stored) for g in encoded),
        "fragment_metadata_bytes": HEADER * compressed_packets,
        "fragment_signature_bytes": SIGNATURE * compressed_packets,
        "padding_bytes": 0, "compressed_data_packets": compressed_packets,
        "raw_data_packets": raw_packets,
        "compressed_data_wire_bytes": sum(compressed_sizes) * recipients,
        "raw_data_wire_bytes": sum(raw_sizes),
        "compressed_progress_poll_pairs": compressed_polls,
        "raw_progress_poll_pairs": raw_polls,
        "compressed_group_census_pairs": len(encoded) * recipients,
        "compressed_data_air_s": compressed_air, "raw_data_air_s": raw_air,
        "compressed_checkpoint_air_s": compressed_control_air, "raw_checkpoint_air_s": raw_control_air,
        "estimates_only": True,
        "excludes": "admission/lease/COMMIT/final survey, loss, repairs, stock whole-second counters, "
                    "TX-completion pacing, contention and flash/decode CPU; no hardware timing claim",
    }
    return encoded, result
