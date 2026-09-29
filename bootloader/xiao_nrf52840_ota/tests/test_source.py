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

print("xiao OTA boot source-order tests passed")
