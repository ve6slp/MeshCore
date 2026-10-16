#!/usr/bin/env python3
"""Offline production encoder/wire and genuine linked-image resource report."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import lzma
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import ota_compression as codec
import ota_stock_companion as stock


def run(*command):
    return subprocess.check_output(command, text=True)


def symbols(prefix, elf):
    found = {}
    for line in run(prefix + "nm", "-S", "-C", "--size-sort", str(elf)).splitlines():
        match = re.match(r"([0-9a-f]+) ([0-9a-f]+) (\w) (.*)", line)
        if match:
            address, size, kind, name = match.groups()
            found[name] = {"address": int(address, 16), "bytes": int(size, 16), "kind": kind}
    return found


def resource_report(args):
    if not args.elf:
        return {"measured": False, "reason": "pass --elf and run ota-compression-arm-size"}
    found = symbols(args.arm_prefix, args.elf)
    probe = symbols(args.arm_prefix, args.probe)
    decoder = {name: value for name, value in found.items() if any(token in name for token in (
        "OtaLzma::", "LzmaDec_", "z7_BranchConv_ARMT_Dec"))}
    result = {
        "measured": True, "genuine_app_elf": str(args.elf.resolve()),
        "compiler": run(args.arm_prefix + "gcc", "--version").splitlines()[0],
        "elf_sha256": hashlib.sha256(args.elf.read_bytes()).hexdigest(),
        "linked_size": run(args.arm_prefix + "size", str(args.elf)),
        "linked_sections": run(args.arm_prefix + "size", "-A", str(args.elf)),
        "decoder_linked_symbols": decoder,
        "decoder_linked_code_and_readonly_bytes": sum(v["bytes"] for v in {
            (v["address"], v["bytes"]): v for v in decoder.values()}.values()),
        "decoder_workspace_bytes": probe["ota_decoder_workspace"]["bytes"],
        "input_buffer_bytes": probe["ota_decoder_input"]["bytes"],
        "output_buffer_bytes": probe["ota_decoder_output"]["bytes"],
        "receiver_instance_bytes": probe["ota_receiver_size"]["bytes"],
        "owned_compression_state_bytes": probe["ota_compression_state_size"]["bytes"],
        "separate_32k_history_bytes": 0, "decoder_heap_bytes": 0,
        "probability_bytes": 7040, "decode_slice_input_max": 128, "decode_slice_output_max": 128,
        "decoder_slices_max": 130, "filter_slice_bytes_max": 128, "crc_slice_bytes_max": 128,
        "crc_bit_iterations_max": 8064 * 8,
        "flash_work": "one raw84 preflight read, raw84 program, or bitmap publish per mesh tick; bitmap publication starts only after full group program",
        "runtime_limit": "one finite SDK call per normal mesh tick, plus separate filter/CRC stages; no measured nRF latency/watchdog claim",
        "on_device_probe": "admin encrypted ota codec / ota_management.py codec: worst measured slice_us, cumulative validation group_us, sampled minimum heap and RTOS stack-free bytes; no keys",
        "stack_note": "GCC .su static frames, excluding interrupts, virtual callers and prebuilt memcpy; not total RTOS stack proof",
    }
    if args.stack_dir:
        entries = []
        for path in args.stack_dir.rglob("*.su"):
            for line in path.read_text().splitlines():
                if any(token in line for token in (
                        "OtaLzma::", "LzmaDec_", "BranchConv_ARMT", "handleCompressedFragment(",
                        "advanceCompressedGroup(", "advanceCompressedCodec",
                        "handleLeanControlFrame(", "handleReceivedFrame(", "onControlDataRecv(")):
                    entries.append({"file": str(path), "entry": line})
        result["genuine_app_reachable_stack_frames"] = entries
        path = ("advanceCompressedCodec()", "advanceCompressedCodecSlice()", "OtaLzma::step()",
                "LzmaDec_DecodeToDic", "LzmaDec_DecodeReal_3")
        frames = {name: max((int(item["entry"].split("\t")[1]) for item in entries
                            if name in item["entry"]), default=None) for name in path}
        result["decoder_active_callchain_local_frames"] = frames
        if all(value is not None for value in frames.values()):
            result["decoder_active_callchain_local_stack_bytes"] = sum(frames.values())
        result["decoder_stack_reserve_bytes"] = 1024
    if args.baseline_elf:
        previous = symbols(args.arm_prefix, args.baseline_elf)
        result["baseline_linked_size"] = run(args.arm_prefix + "size", str(args.baseline_elf))
        result["baseline_linked_sections"] = run(args.arm_prefix + "size", "-A", str(args.baseline_elf))
        def sections(text):
            return {match[1]: int(match[2]) for line in text.splitlines()
                    if (match := re.match(r"(\.\S+)\s+(\d+)\s+\d+", line))}
        current_sections, old_sections = sections(result["linked_sections"]), sections(result["baseline_linked_sections"])
        result["section_delta_bytes"] = {name: value - old_sections.get(name, 0)
                                         for name, value in current_sections.items()}
        result["the_mesh_static_delta_bytes"] = found["the_mesh"]["bytes"] - previous["the_mesh"]["bytes"]
        result["baseline_note"] = "genuine precompression ROLE1 APP; frozen radio/build constants may differ, so not a perfectly controlled whole-image code delta"
    return result


def measure(name, image, synthetic, arm_thumb, route):
    groups, decision = codec.plan(image, arm_thumb=arm_thumb, **route)
    # Public deterministic benchmark key/context only; never any deployed key.
    key = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    target, nonce = bytes(range(32)), bytes([0x42]) * 16
    manifest = hashlib.sha256(b"offline-report-manifest" + hashlib.sha256(image).digest()).digest()
    lengths, transcript = [], hashlib.sha256()
    width, hops, retry = route["width"], route["hops"], route["retry"]
    path = bytes([0x73]) * (width * hops)
    for group in groups:
        for prefix in group.fragments(manifest, decision["capacity"]):
            signature = key.sign(codec.signed_message(target, manifest, 1, nonce, prefix))
            inner = prefix + signature
            if retry:
                inner = stock.retry_frame(inner, 1, True)
            packet = stock.packet(inner, path, width)
            assert len(packet) + 3 <= 176
            lengths.append(len(packet))
            transcript.update(packet)
    assert len(lengths) * route["recipients"] == decision["compressed_data_packets"]
    assert sum(lengths) * route["recipients"] == decision["compressed_data_wire_bytes"]
    decision.update(
        name=name, synthetic_control=synthetic,
        stored_ratio=decision["stored_bytes"] / len(image),
        raw_fallback_group_fraction=decision["raw_fallback_groups"] / len(groups),
        raw_fallback_byte_fraction=sum(g.raw_bytes for g in groups if g.profile == codec.RAW) / len(image),
        verified_actual_frame_transcript_sha256=transcript.hexdigest(),
        max_data_rf_bytes=max(lengths), max_data_usb_tx_bytes=max(lengths) + 2,
        max_data_usb_rx_bytes=max(lengths) + 3,
        data_packet_saving_fraction=1 - decision["compressed_data_packets"] / decision["raw_data_packets"],
        new_control_max_usb_rx_bytes=95 + 5 * retry + 2 + len(path) + 3,
        # Existing targeted AUTH is larger than new compressed controls. Do not
        # hide this legacy control/path limitation behind a safe data capacity.
        existing_auth_usb_rx_full_path_bound=164 + 5 * retry + 2 + len(path) + 3,
    )
    for strategy in ("compressed", "raw"):
        air = decision[strategy + "_data_air_s"] + decision[strategy + "_checkpoint_air_s"]
        decision[strategy + "_estimated_duty_hours"] = {
            str(duty): {"physical": air / duty / 3600, "stock_1p5_guard": 1.5 * air / duty / 3600}
            for duty in (.02, .03)}
    return decision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, action="append", required=True,
                        help="explicit nRF firmware input; authenticated Thumb profile")
    parser.add_argument("--portable-image", type=Path, action="append", default=[],
                        help="explicit non-Thumb/ESP input")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--baseline-elf", type=Path)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--stack-dir", type=Path)
    parser.add_argument("--arm-prefix", default="arm-none-eabi-")
    args = parser.parse_args()
    inputs = [(str(path.parent), path.read_bytes(), False, True) for path in args.image]
    inputs += [(str(path.parent), path.read_bytes(), False, False) for path in args.portable_image]
    inputs.extend([
        ("synthetic-incompressible", hashlib.shake_256(b"OTA report random control").digest(510388), True, False),
        ("synthetic-repetitive", (b"MeshCore bounded compression control\n" * 15000)[:510388], True, False),
    ])
    routes = [
        dict(width=1, hops=0, retry=False, recipients=1),
        dict(width=1, hops=1, retry=True, recipients=1),
        dict(width=2, hops=1, retry=True, recipients=1),
        dict(width=3, hops=1, retry=True, recipients=1),
        dict(width=1, hops=1, retry=True, recipients=2),
        dict(width=1, hops=63, retry=True, recipients=2),
    ]
    report = {
        "codec": "independent raw LZMA1, lc0/lp1/pb1/dict8192/group8064, normal/BT4/nice273/depth1000; explicit nRF ARMT",
        "host_encoder": {"library": "Python stdlib lzma / system liblzma", "python_version": sys.version,
                         "module": lzma.__file__},
        "embedded_decoder": {"source": "src/helpers/ota/OtaLzma.h",
                             "origin": "unmodified 7-Zip/LZMA SDK26.04 C persistent dictionary API and ARMT filter",
                             "license": "public-domain selected files; full upstream License.txt and URL/SHA provenance retained"},
        "hardware_qualified": False,
        "air_model": "BW62.5kHz SF7 CR5 preamble32; estimated cumulative data/checkpoint air, NOT elapsed hardware completion time",
        "route_note": "capacity includes 176B TX/RX framing and growth; legacy_control_path_supported=false routes are packet-model-only and selected product streams explicitly refuse them before admission. Zero-hop uses the same SF7/BW62.5 model for framing comparison, not the stock off-normal direct SF5/BW250 workflow.",
        "source_sha256": {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in (
            "scripts/ota_compression.py", "scripts/ota_stock_companion.py",
            "src/helpers/ota/OtaCompressionWire.h", "src/helpers/ota/OtaLzma.h",
            "src/helpers/ota/third_party/lzma/LzmaDec.c", "src/helpers/ota/third_party/lzma/Bra.c")},
        "resources": resource_report(args),
        "measurements": [measure(name, image, synthetic, arm_thumb, route)
                         for name, image, synthetic, arm_thumb in inputs for route in routes],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("name / route / raw→compressed packets / stored ratio / selected")
    for row in report["measurements"]:
        if row["path_width"] == 1 and row["max_relay_hops"] == 1:
            print(f'{row["name"]} / one-hop ×{row["recipient_bound_streams"]} / '
                  f'{row["raw_data_packets"]}→{row["compressed_data_packets"]} / '
                  f'{row["stored_ratio"]:.3%} / {row["selected"]}')
    print("Persistent report:", args.output)


if __name__ == "__main__":
    main()
