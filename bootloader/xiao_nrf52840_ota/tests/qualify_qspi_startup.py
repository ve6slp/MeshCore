#!/usr/bin/env python3
"""Qualify production wake/idle behavior against the retained F1 source."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess

from qualify_qspi_adapter import replace_function, replace_once


F1_SHA256 = "4cdfab36cfd2efda9a8c789e9d531bbe7388425ef523a49b543b576eeb5db399"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--baseline-source", required=True)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--role-id", type=int, choices=(0, 1), default=1)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    work = Path(args.work_dir).resolve()
    work.relative_to(root / ".tmp")
    work.mkdir(parents=True, exist_ok=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = (root / "bootloader/xiao_nrf52840_ota/src/xiao_ota_boot.c").read_text()
    baseline = Path(args.baseline_source).read_text()
    assert hashlib.sha256(baseline.encode()).hexdigest() == F1_SHA256, (
        "baseline must be the retained, qualified F1 adapter"
    )
    no_wake = replace_function(
        source, "qspi_wake_and_wait_idle",
        lambda body: "static bool qspi_wake_and_wait_idle(qspi_deadline_t *deadline) {\n"
                     "  return qspi_wait_flash_write_complete(deadline);\n}\n",
    )
    no_idle = replace_function(
        source, "qspi_wake_and_wait_idle",
        lambda body: replace_once(body, "return qspi_wait_flash_write_complete(deadline);",
                                  "return true;"),
    )
    renewed_budget = replace_function(
        source, "qspi_wake_and_wait_idle",
        lambda body: replace_once(body, "return qspi_wait_flash_write_complete(deadline);",
                                  "deadline->cycles *= 2u;\n"
                                  "  return qspi_wait_flash_write_complete(deadline);"),
    )
    short_activation = replace_function(
        source, "hw_qspi_init",
        lambda body: replace_once(body, "qspi_wait_ready(&deadline, NULL)",
                                  "qspi_wait_for(10u)"),
    )
    start = source.index("static void qspi_quiesce(void) {")
    end = source.index("\n}\n", start) + 3
    no_quiesce = source[:start] + "static void qspi_quiesce(void) {}\n" + source[end:]
    controls = [
        ("f1-before-wake", baseline, "deep-powerdown",
         "sleeping flash was not woken before identification"),
        ("f1-mid-erase", baseline, "mid-erase",
         "startup identified flash before its erase completed"),
        ("wake-removed", no_wake, "deep-powerdown",
         "sleeping flash was not woken before identification"),
        ("tres-delay-removed", replace_once(source, "NRFX_DELAY_US(10u);", "(void)deadline;"),
         "deep-powerdown", "command issued before tRES elapsed"),
        ("initial-idle-removed", no_idle, "mid-erase",
         "startup identified flash before its erase completed"),
        ("startup-budget-extended", renewed_budget, "startup-deadline",
         "!io->qspi_init(NULL)"),
        ("activation-cap-restored", short_activation, "mid-erase",
         "startup identified flash before its erase completed"),
        ("startup-quiescence-removed", no_quiesce, "wake-error-clock",
         "mock_qspi.ENABLE == QSPI_ENABLE_ENABLE_Disabled"),
        ("startup-clock-escape-removed",
         replace_once(source,
                      "++deadline->stagnant_reads >= XIAO_OTA_HW_DWT_STAGNANT_READ_LIMIT",
                      "++deadline->stagnant_reads == UINT32_MAX"),
         "wake-error-clock", "QSPI wait exceeded finite host observation bound"),
    ]
    report = {"baseline_sha256": F1_SHA256, "role_id": args.role_id, "controls": []}
    for name, fixture, case, expected in controls + [("fixed", source, "", None)]:
        directory = work / name
        directory.mkdir(exist_ok=True)
        adapter = directory / "xiao_ota_boot.c"
        adapter.write_text(fixture)
        command = [
            "make", "--no-print-directory", "test-xiao-ota-qspi-startup",
            f"TMPDIR={directory}", f"XIAO_OTA_UPSTREAM={Path(args.upstream).resolve()}",
            f"CC={args.cc}", f"XIAO_OTA_QSPI_ADAPTER_SOURCE={adapter}",
            f"XIAO_OTA_ROLE_ID={args.role_id}", f"XIAO_OTA_QSPI_TEST_CASE={case}",
        ]
        result = subprocess.run(command, cwd=root, env=os.environ.copy(), text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        log = directory / "make.log"
        log.write_text(result.stdout)
        if expected is None:
            assert result.returncode == 0 and result.stdout.count("PASS ") == 4, log
        else:
            assert result.returncode != 0, f"control unexpectedly passed: {log}"
            assert f"RUN {case}" in result.stdout, f"control did not execute: {log}"
            assert "Assertion" in result.stdout and expected in result.stdout, (
                f"control did not reach its behavioral assertion: {log}"
            )
        report["controls"].append({
            "name": name, "command": command, "exit_code": result.returncode,
            "expected_assertion": expected, "log": str(log),
            "source_sha256": hashlib.sha256(fixture.encode()).hexdigest(),
        })
        print(f"{'PASS' if expected is None else 'EXPECTED ASSERTION FAILURE'} {name}: {log}")
    (work / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
