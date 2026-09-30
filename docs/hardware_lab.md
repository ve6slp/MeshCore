# Hardware lab device workflow

Every operation against a physical board goes through one tool,
`scripts/lab_device.py`, wrapped by `make lab-*` targets. No target, script, or
ad-hoc command names a `ttyACM` number or a literal USB serial.

## Host dependencies

The lab scripts need Python packages beyond the base toolchain. Install them
before running any `make lab-*` target or the host-side tests:

```sh
python3 -m pip install -r requirements-ota.txt
```

This pins `cryptography>=43.0` and `pyserial>=3.5`.

`make test-ota-lab-host` runs the host-side unit tests for
`scripts/lab_device.py` and `scripts/ota_rf_lab.py` (`scripts/tests/`),
including the protected-power-domain behaviour described below. It exercises
the actual wire/USB-protection logic against mocked device topology, not a
placeholder or infrastructure-only check. It is part of `make test`/`make
test-ota` and does not require a board attached.

## Roles, not ports

Boards are addressed by **role**. `lab/devices.ini` pins each role to a USB
serial:

```ini
[roles]
client = 4186AE911D94CDB1
target = 3BE94917B92DC5E9

[protected]
pine = 49C5BAF21EEF44A1
```

Override a role for one run without editing the file:

```sh
MESHCORE_LAB_TARGET_SERIAL=ABC123 make lab-devices
```

Serials in `[protected]` cannot be assigned to a lab role, including through
an environment override. This prevents the Pine project board from being
reset, flashed, or power-cycled by a MeshCore lab command.

`ttyACM` numbering changes whenever a board re-enumerates — a DFU entry alone
moves it. Resolving a role to the current `/dev/serial/by-id` path at the moment
of use makes that a non-event.

## Commands

| Command | Purpose |
| --- | --- |
| `make lab-devices` | List attached boards, their roles, mode, and hub port |
| `make lab-doctor` | Check sudo, uhubctl, pyserial, and per-role power control |
| `make lab-reset-<role>` | Restart the application firmware |
| `make lab-bootloader-<role>` | Enter the serial DFU bootloader |
| `make lab-power-cycle-<role>` | Cut and restore USB port power |
| `make lab-wait-<role>` | Block until the board enumerates |
| `make upload-xiao-nrf52-<role>` | Build and flash the companion lab firmware |

## Why these mechanisms

**Mode detection uses the USB product ID, not product strings.** The Adafruit
nRF52 core sets bit 15 of the PID in the application and clears it in the
bootloader (`0x8044` vs `0x0045`). Product strings differ between board
variants and between modes, so matching on them is unreliable.

**Bootloader entry opens the port at 1200 baud and drops DTR.** The core
triggers on the DTR high-to-low edge at that line rate. Re-rating an
already-open port with `termios` works on some boards and silently does nothing
on others.

**Discovery waits for the by-id symlink.** A board appears in sysfs before udev
applies permissions and creates the stable symlink. Acting on the raw
`/dev/ttyACMn` node in that window fails with `EACCES`.

**Flashing drives `adafruit-nrfutil` directly.** PlatformIO's uploader always
issues its own 1200-baud touch and then rediscovers the port by scanning, which
fails when the board is already in DFU or when numbering shifts mid-upload.
Pointing `adafruit-nrfutil` at an already-resolved DFU port is deterministic.

**Power cycling uses `uhubctl -f`, never the sysfs `authorized` toggle.** The
`authorized` toggle looks like a reasonable fallback but leaves the
nRF52840 USB stack wedged (`can't set config #1, error -32`), recoverable
only by a real power cut or a physical reset. It cost the lab one board
before this was understood.

## Protected power domains

The bench hubs report ganged power switching: forcing a port off/on with
`uhubctl -f` can affect every device sharing that hub, not just the port
you asked for. `scripts/lab_device.py` therefore refuses to run `uhubctl`
against **any** hub that also carries a device listed under `[protected]`
in `lab/devices.ini`, even with `-f`, even for a role that isn't itself
protected.

Right now the `target` role and the protected Pine board are both attached
under the same physical hub (`target` at `1-4.2.3`, Pine at `1-4.2.1.2`,
sharing parent hub `1-4.2`). `make lab-power-cycle-target` will refuse and
print `refusing to power-cycle hub 1-4.2: protected device shares its power
domain` instead of touching `uhubctl`. Recovering `target` in that state
needs a physical reset or replug, not a lab command. `make lab-doctor`
reports this case as `physical reset required`.

`client` is on a separate, isolated bus and is not affected — `uhubctl`
power-cycling for `client` continues to work normally through the same
`make lab-power-cycle-client` target. This isolation depends on physical
wiring, not configuration, and can change if boards are moved to different
hub ports.

## What this lab has verified for LoRa OTA

This bench pair is currently used to validate the LoRa OTA subsystem. What is
proven here is application-level radio behaviour and raw/staged flash
correctness on the `target` board — not a completed firmware install. The
custom bootloader that would turn a staged image into a running update is
built and tested separately and remains unproven end to end. See the
[LoRa OTA developer guide](lora_ota_development.md#current-hardware-evidence)
for the current, dated evidence ledger and its explicit gaps before quoting
any hardware result from this lab elsewhere.

## Bootloader commissioning preflight

The preflight is **read-only by default**, uses the stable `target` identity
and never resets, flashes or power-cycles a board:

```sh
make inspect-xiao-nrf52-boot-journal
```

It requires the lab firmware's eight-sector read interface; older lab
images refuse the request rather than returning a successful preflight.
Each pass archives all 4,096 bytes of both floor sectors and the six
command, state and confirmation sectors. Two passes must match. Dumps,
SHA-256 hashes and device/application identity are recorded under
`.tmp/ota-boot-preflight/`.

The only nonempty floor allowed for historical lab cleanup is the exact
37-byte diagnostic pattern at floor-A offsets 3–39, with every other byte
erased. Floor-B and all transaction sectors must be entirely erased.
Existing counters, unknown bytes, pending transactions or inconsistent
reads stop the procedure; they must never be reinterpreted as counter zero.

After reviewing that evidence and confirming its historical lab provenance,
`make clean-xiao-nrf52-legacy-floor` explicitly approves cleanup of that
single known floor-A sector. It re-reads the journal immediately before the
request and archives two full post-cleanup passes. This is not routine
maintenance and never authorizes erasing a valid floor or the wider journal.
A passing preflight does **not** qualify the bootloader or prove an OTA install.

## Recovering an unresponsive board

`make lab-reset-client` and `make lab-reset-target` send the companion
firmware's binary `reboot` command and require USB disconnection followed by
application re-enumeration. DTR/RTS toggling alone does not reset these
boards. Firmware without that command, including the QSPI diagnostic image,
needs DFU entry or a physical reset instead.

```sh
make lab-devices           # is it present at all?
make lab-power-cycle-target
make upload-xiao-nrf52-target
```

`lab-power-cycle` locates the board in sysfs by serial rather than by role
resolution, so it still works on a board that exposes no serial port.

`lab-power-cycle-target` currently refuses, per
[Protected power domains](#protected-power-domains) above, because `target`
shares a hub with the protected Pine board. If it refuses, physically reset
or replug `target` instead, then continue with `make upload-xiao-nrf52-target`.

If `make lab-doctor` reports `physical reset required` for a role, that port has
no software power control (or, as with `target` today, shares a hub with a
protected device), and the board's reset button or a manual replug is the
only recovery.
