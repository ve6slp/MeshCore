# Hardware lab device workflow

Every operation against a physical board goes through one tool,
`scripts/lab_device.py`, wrapped by `make lab-*` targets. No target, script, or
ad-hoc command names a `ttyACM` number or a literal USB serial.

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
bench hubs report ganged power switching, so uhubctl skips them without `-f`
even though per-port switching works. The `authorized` toggle looks like a
reasonable fallback but leaves the nRF52840 USB stack wedged
(`can't set config #1, error -32`), recoverable only by a real power cut or a
physical reset. It cost the lab one board before this was understood.

## Recovering an unresponsive board

```sh
make lab-devices           # is it present at all?
make lab-power-cycle-target
make upload-xiao-nrf52-target
```

`lab-power-cycle` locates the board in sysfs by serial rather than by role
resolution, so it still works on a board that exposes no serial port.

If `make lab-doctor` reports `physical reset required` for a role, that port has
no software power control and the board's reset button is the only recovery.
