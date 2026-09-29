#!/usr/bin/env python3
"""Report linker-defined bootloader FLASH load usage."""

import argparse
import subprocess


parser = argparse.ArgumentParser()
parser.add_argument("elf")
parser.add_argument("--slot-bytes", type=int, required=True)
args = parser.parse_args()

symbols = {}
output = subprocess.check_output(
    ["arm-none-eabi-nm", "-n", args.elf], text=True
)
for line in output.splitlines():
    fields = line.split()
    if len(fields) == 3 and fields[2] in {
        "CodeFlashUsed", "DataInitFlashUsed", "TotalFlashUsed"
    }:
        symbols[fields[2]] = int(fields[0], 16)

missing = {"CodeFlashUsed", "DataInitFlashUsed", "TotalFlashUsed"} - symbols.keys()
if missing:
    raise SystemExit(f"missing linker size symbols: {', '.join(sorted(missing))}")

total = symbols["TotalFlashUsed"]
free = args.slot_bytes - total
print(
    f"FLASH load: {total} / {args.slot_bytes} bytes "
    f"({100.0 * total / args.slot_bytes:.2f}%), {free} bytes free; "
    f"code/rodata={symbols['CodeFlashUsed']}, "
    f"initialized-data={symbols['DataInitFlashUsed']}"
)
