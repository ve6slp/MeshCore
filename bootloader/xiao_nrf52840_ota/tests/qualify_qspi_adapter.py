#!/usr/bin/env python3
"""Causal host qualification of the production adapter, built only via Make."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise AssertionError("mutation anchor must match exactly once")
    return text.replace(old, new, 1)


def replace_function(text, name, transform):
    start = text.index(f"static bool {name}(")
    end = text.index("\n}\n", start) + 3
    return text[:start] + transform(text[start:end]) + text[end:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--role-id", type=int, choices=(0, 1), default=0)
    parser.add_argument("--board-target", default="XIAO_OTA_TARGET_XIAO_NRF52840")
    parser.add_argument("--baseline-ref", default="ccc0a77b1813a3999dadb2ca465e42261f2f68ac")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    work = Path(args.work_dir).resolve()
    work.relative_to(root / ".tmp")  # all outputs stay on project disk
    work.mkdir(parents=True, exist_ok=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    relative_source = "bootloader/xiao_nrf52840_ota/src/xiao_ota_boot.c"
    source = (root / relative_source).read_text()
    baseline = subprocess.check_output(
        ["git", "show", f"{args.baseline_ref}:{relative_source}"], cwd=root, text=True
    )
    completion = (
        "return qspi_wait_ready(&deadline, NULL) &&\n"
        "         qspi_wait_flash_write_complete(&deadline);"
    )

    def no_completion(body):
        return replace_once(body, completion, "return qspi_wait_ready(&deadline, NULL);")

    quiesce_start = source.index("static void qspi_quiesce(void) {")
    quiesce_end = source.index("\n}\n", quiesce_start) + 3
    no_quiesce = source[:quiesce_start] + "static void qspi_quiesce(void) {}\n" + source[quiesce_end:]
    controls = [
        ("before-fix-erase", baseline, "delayed-erase", "erase returned before flash WIP cleared"),
        ("before-fix-buffer", baseline, "pending-buffer", "returned buffer was consumed after timeout"),
        ("erase-completion-removed",
         replace_function(source, "hw_qspi_erase_sector", no_completion),
         "delayed-erase", "erase returned before flash WIP cleared"),
        ("program-completion-removed",
         replace_function(source, "hw_qspi_write", no_completion),
         "program-busy", "program returned before flash WIP cleared"),
        ("quiescence-removed", no_quiesce,
         "pending-buffer", "returned buffer was consumed after timeout"),
        ("operation-deadline-restarted",
         replace_function(source, "hw_qspi_write", lambda body: replace_once(
             body, completion,
             "if (!qspi_wait_ready(&deadline, NULL)) return false;\n"
             "  qspi_deadline_start(&deadline, XIAO_OTA_HW_QSPI_PROGRAM_TIMEOUT_MS);\n"
             "  return qspi_wait_flash_write_complete(&deadline);")),
         "deadline", "program restarted its deadline after transfer"),
        ("clock-liveness-removed",
         replace_once(source,
                      "++deadline->stagnant_reads >= XIAO_OTA_HW_DWT_STAGNANT_READ_LIMIT",
                      "++deadline->stagnant_reads == UINT32_MAX"),
         "stopped-clock", "QSPI wait exceeded finite host observation bound"),
    ]
    report = {"baseline_ref": args.baseline_ref, "role_id": args.role_id,
              "board_target": args.board_target, "controls": []}
    env = os.environ.copy()
    for name, fixture, case, expected in controls + [("fixed", source, "", None)]:
        directory = work / name
        directory.mkdir(exist_ok=True)
        adapter = directory / "xiao_ota_boot.c"
        adapter.write_text(fixture)
        command = [
            "make", "--no-print-directory", "test-xiao-ota-qspi-adapter",
            f"TMPDIR={directory}", f"XIAO_OTA_UPSTREAM={Path(args.upstream).resolve()}",
            f"CC={args.cc}", f"XIAO_OTA_QSPI_ADAPTER_SOURCE={adapter}",
            f"XIAO_OTA_ROLE_ID={args.role_id}",
            f"XIAO_OTA_TEST_BOARD_TARGET={args.board_target}",
            f"XIAO_OTA_QSPI_TEST_CASE={case}",
        ]
        result = subprocess.run(command, cwd=root, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        log = directory / "make.log"
        log.write_text(result.stdout)
        if expected is None:
            assert result.returncode == 0, f"fixed adapter failed: {log}"
            assert result.stdout.count("PASS ") == 7, f"incomplete positive run: {log}"
        else:
            # A compile/link failure or timeout is NOT a causal negative control.
            assert result.returncode != 0, f"control unexpectedly passed: {log}"
            assert f"RUN {case}" in result.stdout, f"control did not execute: {log}"
            assert "Assertion" in result.stdout and expected in result.stdout, (
                f"control did not fail the expected behavioral assertion: {log}"
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
