#!/usr/bin/env python3
"""Source-order regressions for the pinned upstream boot hook."""

from pathlib import Path


root = Path(__file__).resolve().parents[1]
text = (root / "src" / "xiao_ota_boot.c").read_text()
boot = text[text.index("void xiao_ota_boot_process(void)"):]

bypass = boot.index(
    "if (xiao_ota_explicit_dfu_requested(NRF_POWER->GPREGRET)) return;"
)
qspi = boot.index("qspi_init();")
assert bypass < qspi, "explicit upstream DFU requests must bypass QSPI/OTA work"

candidate_settings = boot.index("write_boot_settings(BANK_VALID_APP")
trial = boot.index("state.phase = XIAO_OTA_PHASE_TRIAL_BOOT;")
assert candidate_settings < trial, "candidate metadata must precede trial state"

rollback = boot.index("if (state.phase == XIAO_OTA_PHASE_ROLLBACK_COPYING)")
restore_settings = boot.index("write_boot_settings(state.previous_bank_0", rollback)
failed = boot.index("state.phase = XIAO_OTA_PHASE_FAILED;", rollback)
assert restore_settings < failed, "rollback metadata restore must precede FAILED"

# The actual "which phases accept a new command" decision now lives in
# xiao_ota_command_acceptable_phase() (xiao_ota_record.c), which is
# host-testable and behaviourally exercised for every phase value in
# test_record.c. Here we only confirm the boot hook calls that real function
# (not a re-inlined, possibly-drifted copy of the same condition) and still
# reaches command_policy_valid() before re-arming BACKUP_COPYING.
accept_gate = boot.index("if (xiao_ota_command_acceptable_phase(")
accept_gate_end = boot.index(") {", accept_gate)
policy_check_after_gate = boot.index("command_policy_valid(&command", accept_gate_end)
backup_copying_after_gate = boot.index(
    "state.phase = XIAO_OTA_PHASE_BACKUP_COPYING;", accept_gate_end
)
assert policy_check_after_gate < backup_copying_after_gate, (
    "a command accepted by xiao_ota_command_acceptable_phase() must still "
    "pass command_policy_valid() before re-arming BACKUP_COPYING"
)

print("xiao OTA boot source-order tests passed")

# QSPI EasyDMA (WRITE.SRC) on the nRF52840 can only address Data RAM; it
# cannot DMA straight out of internal code flash. copy_internal_to_qspi()
# backs up the running application (code flash) into the QSPI backup bank,
# so its qspi_write() must be given a RAM staging buffer, never a pointer
# built from XIAO_OTA_APP_START.
copy_internal = text[text.index("static bool copy_internal_to_qspi"):
                     text.index("static bool copy_qspi_to_internal")]
qspi_write_call = copy_internal.index("qspi_write(XIAO_OTA_BACKUP_BASE")
call_end = copy_internal.index(";", qspi_write_call)
qspi_write_args = copy_internal[qspi_write_call:call_end]
assert "XIAO_OTA_APP_START" not in qspi_write_args, (
    "qspi_write() source must not be a code-flash pointer; QSPI EasyDMA "
    "requires a RAM source buffer"
)

print("xiao OTA QSPI EasyDMA source-buffer test passed")
