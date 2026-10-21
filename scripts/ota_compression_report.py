#!/usr/bin/env python3
"""Actual v4 encoder/frame accounting; estimates are not physical measurements."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

from ota_common import Frame, Kind, physical_airtime
from ota_compression import Package
from ota_job import JobStore
from ota_transport import Route

SOLAR_V3 = {"image_bytes": 519940, "stored_bytes": 335494, "raw_group_bytes": 8064,
            "data_frames": 4074, "group_progress_tx": 1299, "census_tx": 115,
            "authorization_tx": 1, "capability_tx": 1, "total_tx": 5490,
            "elapsed_s": 7505.821,
            "image_sha256": "2f548dab7cbefea792e1ce2d73205b9a0233f3f1b5c6c95d9b73093ddfb27c85",
            "source": "published prior Solar v3 campaign; elapsed time is not measured airtime"}


def measure(package, route, recipients=1, bandwidth=62500, sf=7, cr=5):
    route.validate()
    if not 1 <= recipients <= 32:
        raise ValueError("1..32 recipients required")
    counts = {}

    def object_frames(kind, size, copies=1, direction="tx"):
        sizes = []
        for index in range((size + 127) // 128):
            payload = bytes(min(128, size - index * 128))
            sizes.append(len(Frame(kind, 1, package.tag, 0, size, index, payload).encode()))
        ota_bytes = sum(sizes) * copies
        # Use the declared maximum grown path, separately from actual job TX.
        rf_sizes = [n + 2 + route.max_path_bytes for n in sizes]
        command = 2 if direction == "tx" else 3
        entry = counts.setdefault(direction + "/" + kind.name.lower(),
                                  {"frames": 0, "ota_bytes": 0, "mesh_bytes": 0,
                                   "stock_serial_payload_bytes": 0, "stock_serial_wire_bytes": 0,
                                   "native_serial_payload_bytes": 0, "native_serial_wire_bytes": 0,
                                   "mesh_header_bytes": 0, "mesh_path_bytes": 0,
                                   "estimated_air_s": 0})
        entry["frames"] += len(sizes) * copies
        entry["ota_bytes"] += ota_bytes
        entry["mesh_bytes"] += sum(rf_sizes) * copies
        entry["mesh_header_bytes"] += 2 * len(sizes) * copies
        entry["mesh_path_bytes"] += route.max_path_bytes * len(sizes) * copies
        entry["stock_serial_payload_bytes"] += sum(n + command for n in rf_sizes) * copies
        entry["stock_serial_wire_bytes"] += sum(n + command + 3 for n in rf_sizes) * copies
        native_command = 3 if direction == "tx" else 1
        entry["native_serial_payload_bytes"] += sum(n + native_command for n in rf_sizes) * copies
        entry["native_serial_wire_bytes"] += sum(n + native_command + 3 for n in rf_sizes) * copies
        entry["estimated_air_s"] += sum(physical_airtime(n, bandwidth, sf, cr) for n in rf_sizes) * copies

    object_frames(Kind.MANIFEST, len(package.manifest))
    for chunk in package.chunks:
        object_frames(Kind.DATA, len(chunk.stored))
    bursts = sum(math.ceil(math.ceil(len(c.stored) / 128) / 16) for c in package.chunks)
    surveys = 7 + bursts // 8
    # The scheduler's no-loss, immediate-processing scenario. Real extra polls,
    # repairs and interrupted transmissions are captured in the durable job.
    reply_path_bytes = len(route.reply_path())
    object_frames(Kind.QUERY, 48 + reply_path_bytes, recipients * surveys)
    object_frames(Kind.STATUS, 233, recipients * surveys, "rx")
    object_frames(Kind.ADMIT, 180, recipients)
    object_frames(Kind.ACTIVATE, 180, recipients)
    object_frames(Kind.PROGRESS_QUERY, 32 + reply_path_bytes, recipients * bursts)
    object_frames(Kind.PROGRESS, 48, recipients * bursts, "rx")
    host_air = sum(c["estimated_air_s"] for k, c in counts.items() if k.startswith("tx/"))
    reply_air = sum(c["estimated_air_s"] for k, c in counts.items() if k.startswith("rx/"))
    return {"version": 4, "image_bytes": len(package.raw), "image_sha256": package.raw_hash.hex(),
            "package_sha256": package.digest.hex(), "manifest_bytes": len(package.manifest),
            "chunks": len(package.chunks), "codec_chunks": dict(Counter(c.codec for c in package.chunks)),
            "stored_bytes": sum(len(c.stored) for c in package.chunks),
            "fleet_recipients": recipients, "shared_data_streams": 1,
            "route": route.policy(), "counts": counts,
            "estimated_scenario_air_s": sum(c["estimated_air_s"] for c in counts.values()),
            "estimated_host_tx_air_s": host_air, "estimated_receiver_reply_air_s": reply_air,
            "stock_guarded_host_tx_air_s": host_air * 1.5,
            "estimated_scenario_tx": sum(c["frames"] for k, c in counts.items() if k.startswith("tx/")),
            "model": {"bandwidth": bandwidth, "sf": sf, "cr": cr},
            "physical_measurement": False,
            "route_model": "actual encoder/frame sizes; every packet charged the declared maximum grown path",
            "scenario": "no loss, immediate receiver work, 16-slice bursts, one final confirmation survey",
            "excludes": "loss/repairs, extra verification polls, leases, contention, CPU/flash time and duty waiting",
            "solar_v3_published_baseline": SOLAR_V3,
            "baseline_comparable_size_only": len(package.raw) == SOLAR_V3["image_bytes"],
            "baseline_same_image": package.raw_hash.hex() == SOLAR_V3["image_sha256"],
            "comparison_requires_matching_radio_and_airtime_scope": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--package", type=Path)
    source.add_argument("--job", type=Path, help="also export historical durable per-kind counters, without device access")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--recipients", type=int, default=1)
    parser.add_argument("--path-bytes", type=int, default=1)
    args = parser.parse_args(argv)
    if args.job is None:
        report = measure(Package.open(args.package), Route(max_path_bytes=args.path_bytes), args.recipients)
    else:
        with JobStore.open(args.job) as job:
            report = measure(job.package, Route.from_policy(job.policy["route"]), len(job.targets))
            row = job.db.execute("SELECT value FROM meta WHERE key='metrics'").fetchone()
            report["historical_job_metrics"] = json.loads(row[0]) if row is not None else None
            report["historical_job_note"] = "recorded counters, not a fresh receiver attestation or total fleet physical airtime"
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"report": str(args.output), "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
