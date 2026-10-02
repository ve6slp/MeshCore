"""Candidate-only FIRMWARE_VERSION override; inherited build flags stay intact."""

import os
import re

Import("env")

label = os.environ.get("XIAO_OTA_LAB_VERSION")
if label is None or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,18}", label) is None:
    raise ValueError(
        "Set XIAO_OTA_LAB_VERSION explicitly: 1..19 ASCII letters/digits/._-, "
        "starting with a letter or digit"
    )

env.Append(CPPDEFINES=[("FIRMWARE_VERSION", env.StringifyMacro(label))])
