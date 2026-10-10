#!/usr/bin/env python3
"""Identity-bound remote OTA CLI over stock encrypted MeshCore management.

Only status/progress/candidate/settings and explicitly selected abort are sent.
No password, contact creation, ACL changes, key export, local CLI, reset, BEGIN
or RF census is used. Provision contacts and receiver admin ACL separately.
Blank CMD26 login requires the sender's existing receiver admin ACL entry.

The stock companion performs pairwise decrypt/MAC verification. USB exposes a
six-byte contact prefix, remote timestamp and plaintext, not the RF MAC/full
identity or a request nonce. Unique contact-prefix guards, queue drain, a fresh
admin login and increasing remote timestamps provide stock-API correlation,
NOT independently verifiable cryptographic request/reply evidence. MeshCore's
wire MAC is only two bytes. Unsigned OTA census is a different transport.
Abort transmits exactly "ota abort <generation> <counter> <image-sha256>".
The receiver must atomically compare those guards before durable mutation;
there is no unguarded/plain-abort fallback. Post-abort readback must prove state.
"""

import argparse
import json
import math
from pathlib import Path
import re
import stat
import struct
import sys
import time

import ota_stock_companion as ota

COMMANDS = {name: "ota " + name for name in ("status", "progress", "candidate", "settings", "abort")}
ABORT_PATTERN = re.compile(rb"ota abort ([1-9][0-9]{0,9}) (0|[1-9][0-9]{0,9}) ([0-9a-f]{64})")
ABORT_ERRORS = frozenset(("unavailable", "denied", "too late", "I/O error", "mismatch", "busy", "not found"))
PHASES = frozenset(("idle", "erasing", "receiving", "verifying", "ready", "commit-pending",
                    "trial", "installed", "aborted", "failed", "cache-sealed", "unknown"))
MAX_CONTACTS = 4096
MAX_MESSAGES = 256
TRUST = {
    "transport": "stock-encrypted-pairwise-remote-cli",
    "companion_mac_checked": True,
    "authentication_authority": "trusted-stock-companion-firmware-not-host-proof",
    "rf_mac_bytes": 2,
    "host_mac_verified": False,
    "cryptographic_request_correlation": False,
    "identity_binding": "full-contact-key-unique-prefix4-and-prefix6",
    "reply_correlation": "fresh-admin-login-queue-drain-increasing-remote-timestamp",
    "status_authenticated": False,
    "installation_confirmed": False,
}


def abort_command(generation, counter, image):
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in (generation, counter)):
        raise ota.Error("explicit uint32 candidate generation/counter guards required for abort")
    if generation == 0:
        raise ota.Error("positive candidate generation guard required for abort")
    return f"ota abort {generation} {counter} {ota.full_key(image).hex()}".encode("ascii")


def valid_abort_command(command):
    match = ABORT_PATTERN.fullmatch(command)
    return bool(match and all(int(match[index]) <= 0xFFFFFFFF for index in (1, 2))
                and any(bytes.fromhex(match[3].decode("ascii"))))


def fields(operation, text):
    if text.startswith(("Err", "Error", "Unknown", "OTA unsupported")):
        raise ota.Refused("remote OTA command refused or unavailable; payload withheld")
    result = {}
    for item in text.split():
        if "=" not in item:
            raise ota.Error("unexpected remote OTA reply format; payload withheld")
        key, value = item.split("=", 1)
        if key in result or not re.fullmatch(r"[a-z][a-z_]*", key) or not re.fullmatch(r"[a-zA-Z0-9_.%/-]+", value):
            raise ota.Error("invalid remote OTA reply fields; payload withheld")
        result[key] = value
    expected = {
        "status": {"boot", "phase", "floor", "counter", "verified", "image"},
        "progress": {"candidate", "phase", "received", "total", "missing", "bytes", "block"},
        "candidate": {"candidate", "phase", "counter", "generation", "image"},
        "settings": {"mode", "duty"},
    }[operation]
    if (operation in ("candidate", "progress") and result == {"candidate": "none", "phase": "idle"}):
        return result
    if set(result) != expected:
        raise ota.Error("unexpected remote OTA reply schema; payload withheld")
    if "phase" in result and result["phase"] not in PHASES:
        raise ota.Error("invalid remote OTA lifecycle phase")
    for key in ("received", "total", "missing", "bytes", "block", "generation"):
        if key in result and not re.fullmatch(r"[0-9]{1,10}", result[key]):
            raise ota.Error("invalid remote OTA numeric field")
        if key in result and int(result[key]) > 0xFFFFFFFF:
            raise ota.Error("remote OTA numeric field exceeds wire bound")
    for key in ("counter", "floor"):
        if key in result and not re.fullmatch(r"(?:[0-9]{1,10}|unknown)", result[key]):
            raise ota.Error("invalid remote OTA counter/floor")
        if key in result and result[key] != "unknown" and int(result[key]) > 0xFFFFFFFF:
            raise ota.Error("remote OTA counter/floor exceeds wire bound")
    if "image" in result and not re.fullmatch(r"(?:[0-9a-f]{64}|unknown|none)", result["image"]):
        raise ota.Error("invalid remote OTA image field")
    if operation in ("candidate", "progress") and result["candidate"] not in ("receiver", "boot", "cache"):
        raise ota.Error("invalid remote OTA candidate source")
    if operation == "candidate" and ((int(result["generation"]) == 0 and result["phase"] != "aborted")
                                    or result["counter"] == "unknown"
                                    or not re.fullmatch(r"[0-9a-f]{64}", result["image"])):
        raise ota.Error("incomplete remote OTA candidate context")
    if operation == "status" and (result["boot"] not in ("confirmed", "trial", "failed", "unknown")
                                  or result["verified"] not in ("0", "1")):
        raise ota.Error("invalid remote OTA boot status")
    if operation == "progress":
        received, total, missing = (int(result[key]) for key in ("received", "total", "missing"))
        if received > total or missing != total - received or result["block"] != str(ota.BLOCK):
            raise ota.Error("inconsistent remote OTA progress")
    if operation == "settings" and (
            result["mode"] not in ("direct", "routed", "fleet")
            or not re.fullmatch(r"[0-9]{1,3}\.[0-9]%", result["duty"])
            or not 0 <= float(result["duty"][:-1]) <= 100):
        raise ota.Error("invalid remote OTA settings")
    return result


class RemoteManagement:
    def __init__(self, stock, binding, target_name, timeout=30, *, wall_clock=time.time, max_skew=120):
        if (not isinstance(target_name, str) or not 0 < len(target_name.encode()) <= 31 or "\x00" in target_name
                or not math.isfinite(timeout) or not 0 < timeout <= 300
                or not math.isfinite(max_skew) or not 0 < max_skew <= 3600):
            raise ota.Error("explicit target label and bounded timeout/clock skew required")
        if not stock.frames.keep_login_pushes:
            raise ota.Error("management requires login-aware bounded Frames")
        self.stock, self.binding, self.target_name = stock, binding, target_name
        self.timeout, self.wall_clock, self.max_skew = timeout, wall_clock, max_skew
        self.session = False
        self.last_timestamp = None
        self.abort_dispatched = False
        self.discarded_messages = 0
        self.session_deadline = 0
        self.observations = []

    def _command(self, payload, expected, deadline):
        if not self.stock.identified or payload[0] not in (2, 4, 10, 26):
            raise ota.Error("management stock identity/command guard failed")
        if payload[0] in (4, 10) and len(payload) != 1:
            raise ota.Error("management reads do not accept arbitrary parameters")
        if payload[0] == 26 and payload != b"\x1a" + self.binding.target:
            raise ota.Error("only blank existing-ACL login is allowed; no password provisioning")
        if payload[0] == 2:
            text = payload[13:]
            read_commands = [command.encode("ascii") for operation, command in COMMANDS.items() if operation != "abort"]
            if (payload[:13] != b"\x02\x01\x00" + bytes(4) + self.binding.target[:6]
                    or (text not in read_commands and not valid_abort_command(text))):
                raise ota.Error("only identity-bound read-only or guarded OTA CLI text may be sent")
        response = self.stock.frames.command(payload, tuple(expected) + (1,),
                                             min(3, max(0, deadline - self.stock.clock())))
        if response[0] == 1:
            if len(response) != 2:
                raise ota.Error("malformed stock management error; payload withheld")
            raise ota.Refused(f"stock management CMD{payload[0]} refused (code {response[1]})")
        return response

    def contact(self, deadline):
        self.stock.frames.poll(0)
        self.stock.frames.pending = [(t, f) for t, f in self.stock.frames.pending if f[0] not in (3, 4)]
        since = self.stock.clock()
        start = self._command(b"\x04", (2,), deadline)
        if len(start) != 5 or not 0 < struct.unpack_from("<I", start, 1)[0] <= MAX_CONTACTS:
            raise ota.Error("invalid/bounded contact list unavailable")
        count = struct.unpack_from("<I", start, 1)[0]
        found, collisions, keys = None, 0, set()
        for _ in range(count + 1):
            frame = self.stock.frames.wait((3, 4, 1), since, deadline)
            if frame[0] == 1:
                raise ota.Refused("stock contact iteration refused")
            if frame[0] == 4:
                if len(frame) != 5 or len(keys) != count or found is None or collisions != 1:
                    raise ota.Error("target absent, duplicate or ambiguous contact prefix; no mutation permitted")
                if found[33] != 2 or found[100:132].split(b"\x00", 1)[0] != self.target_name.encode():
                    raise ota.Error("target full-key contact type/public label mismatch")
                return
            if len(frame) != 148 or frame[1:33] in keys:
                raise ota.Error("malformed/duplicate stock contact; payload withheld")
            key = frame[1:33]
            keys.add(key)
            if key[:4] == self.binding.target[:4] or key[:6] == self.binding.target[:6]:
                collisions += 1
            if key == self.binding.target:
                found = frame
        raise ota.Error("stock contact iterator did not terminate within bound")

    def drain(self, deadline):
        for _ in range(MAX_MESSAGES + 1):
            frame = self._command(b"\x0a", (7, 8, 10, 16, 17, 27), deadline)
            if frame == b"\x0a":
                return
            self.discarded_messages += 1
        raise ota.Error("offline message queue did not drain within bound; payloads withheld")

    def timestamp(self, value):
        if not value or abs(value - self.wall_clock()) > self.max_skew:
            raise ota.Error("remote management clock outside explicit freshness bound; no clock changes")

    @staticmethod
    def sent(frame, login_target=None):
        if (len(frame) != 10 or frame[0] != 6 or frame[1] not in (0, 1)
                or (login_target is not None and frame[2:6] != login_target[:4])
                or (login_target is None and frame[2:6] != bytes(4))):
            raise ota.Error("invalid stock management send admission; payload withheld")

    def login(self):
        self.session = False
        deadline = self.stock.clock() + self.timeout
        self.stock.expected_name = self.binding.sender_name
        if self.stock.key != self.binding.sender or self.stock.identify(deadline)[:4] != self.binding.normal:
            raise ota.Error("management sender full identity/normal profile mismatch; no retune")
        self.contact(deadline)
        self.drain(deadline)
        self.stock.frames.poll(0)
        self.stock.frames.pending = [(t, f) for t, f in self.stock.frames.pending if f[0] not in (0x85, 0x86)]
        since = self.stock.clock()
        self.sent(self._command(b"\x1a" + self.binding.target, (6,), deadline), self.binding.target)
        while self.stock.clock() < deadline:
            frame = self.stock.frames.wait((0x85, 0x86), since, deadline)
            if frame[2:8] != self.binding.target[:6]:
                continue
            if frame[0] == 0x86:
                raise ota.Refused("remote existing-ACL login denied; parent-owned admin provisioning required")
            if len(frame) != 14 or frame[1] != 1 or frame[12] & 3 != 3:
                raise ota.Refused("fresh target login does not prove current admin role")
            self.last_timestamp = struct.unpack_from("<I", frame, 8)[0]
            self.timestamp(self.last_timestamp)
            self.session = True
            self.session_deadline = self.stock.clock() + 300
            return
        raise ota.NoUsbResponse("remote admin login deadline")

    def query(self, operation, *, abort_guard=None):
        if operation not in COMMANDS or not self.session or self.stock.clock() >= self.session_deadline:
            raise ota.Error("explicit allowlisted OTA operation and current admin session required")
        if operation == "abort":
            if not isinstance(abort_guard, tuple) or len(abort_guard) != 3:
                raise ota.Error("remote abort requires guards in the actual encrypted command")
            command = abort_command(*abort_guard)
        else:
            if abort_guard is not None:
                raise ota.Error("abort guards require the explicit abort operation")
            command = COMMANDS[operation].encode("ascii")
        deadline = min(self.stock.clock() + self.timeout, self.session_deadline)
        try:
            self.drain(deadline)
            since = self.stock.clock()
            payload = b"\x02\x01\x00" + bytes(4) + self.binding.target[:6] + command
            if operation == "abort":
                self.abort_dispatched = True
            self.sent(self._command(payload, (6,), deadline))
            messages = 0
            while self.stock.clock() < deadline:
                frame = self._command(b"\x0a", (7, 8, 10, 16, 17, 27), deadline)
                if frame == b"\x0a":
                    self.stock.sleep(min(0.1, max(0, deadline - self.stock.clock())))
                    continue
                messages += 1
                if messages > MAX_MESSAGES:
                    raise ota.Error("remote CLI message scan exceeded bound; payloads withheld")
                if frame[0] != 16:
                    self.discarded_messages += 1
                    continue
                if len(frame) < 16 or frame[2:4] != bytes(2):
                    raise ota.Error("malformed stock v3 management message; payload withheld")
                if frame[4:10] != self.binding.target[:6] or frame[11] != 1:
                    self.discarded_messages += 1
                    continue
                remote_time = struct.unpack_from("<I", frame, 12)[0]
                if self.stock.clock() < since or remote_time <= self.last_timestamp:
                    raise ota.Error("stale/replayed remote CLI response; payload withheld")
                self.timestamp(remote_time)
                try:
                    text = frame[16:].decode("ascii")
                except UnicodeDecodeError as exc:
                    raise ota.Error("non-ASCII remote OTA reply; payload withheld") from exc
                if operation == "abort":
                    if text != "OK - OTA aborted":
                        if text.startswith("Err - OTA abort ") and text[16:] in ABORT_ERRORS:
                            raise ota.Refused(f"remote guarded OTA abort refused: {text[16:]}")
                        raise ota.Refused("remote OTA abort refused/unavailable; payload withheld")
                    parsed = {"abort_acknowledged": True, "durable_abort_confirmed": False}
                else:
                    parsed = fields(operation, text)
                self.last_timestamp = remote_time
                result = {"operation": operation, "target_public_key": self.binding.target.hex(),
                          "remote_timestamp": remote_time, "reply": parsed, **TRUST}
                self.observations = (self.observations + [result])[-16:]
                return result
            raise ota.NoUsbResponse("remote CLI reply deadline; execution outcome unknown")
        except BaseException:
            self.session = False
            raise

    def abort(self, generation, counter, image):
        abort_command(generation, counter, image)
        image = ota.full_key(image).hex()
        before = self.query("candidate")["reply"]
        empty_before = before == {"candidate": "none", "phase": "idle"}
        if not empty_before and (before.get("generation") != str(generation) or before.get("counter") != str(counter)
                                 or before.get("image") != image):
            raise ota.Error("remote abort candidate differs from explicitly selected attempt")
        status_before = self.query("status")
        if status_before["reply"]["floor"] != str(self.binding.floor):
            raise ota.Error("remote pre-abort confirmed floor differs from deployment binding")
        result = self.query("abort", abort_guard=(generation, counter, image))
        after = self.query("candidate")
        progress = self.query("progress")
        status = self.query("status")
        empty = after["reply"] == {"candidate": "none", "phase": "idle"}
        expected_generation = generation if before.get("phase") == "aborted" else generation + 1
        aborted = (after["reply"].get("phase") == "aborted"
                   and after["reply"].get("generation") == str(expected_generation)
                   and all(after["reply"].get(key) == before.get(key) for key in ("counter", "image")))
        confirmed = ((empty or aborted) and progress["reply"].get("phase") in ("idle", "aborted")
                     and status["reply"]["floor"] == str(self.binding.floor))
        boot_fields = ("boot", "floor", "verified", "image")
        boot_unchanged = (status_before["reply"]["boot"] == "confirmed"
                          and status_before["reply"]["verified"] == "1"
                          and re.fullmatch(r"[0-9a-f]{64}", status_before["reply"]["image"]) is not None
                          and all(status_before["reply"][key] == status["reply"][key] for key in boot_fields))
        result.update(candidate_after=after, progress_after=progress, status_before=status_before, status_after=status,
                      confirmed_boot_status_unchanged=boot_unchanged,
                      expected_aborted_generation=expected_generation)
        result["reply"]["durable_abort_confirmed"] = confirmed
        result["outcome"] = "candidate-abort-readback" if confirmed else "transport-stop-only-or-unproven"
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("operation", choices=tuple(COMMANDS))
    parser.add_argument("--serial", required=True)
    parser.add_argument("--by-id", required=True)
    parser.add_argument("--by-path")
    parser.add_argument("--client-dtr", action="store_true")
    parser.add_argument("--sender-key", type=ota.full_key, required=True)
    parser.add_argument("--sender-name")
    parser.add_argument("--target", type=ota.full_key, required=True)
    parser.add_argument("--target-name", required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--max-clock-skew", type=float, default=120)
    parser.add_argument("--expect-generation", type=int)
    parser.add_argument("--expect-counter", type=int)
    parser.add_argument("--expect-image")
    args = parser.parse_args(argv)
    binding = ota.Binding.load(args.binding, args.serial, args.sender_key, args.target, args.by_path, args.sender_name)
    guards = (args.expect_generation, args.expect_counter, args.expect_image)
    if args.operation == "abort" and any(value is None for value in guards):
        raise ota.Error("abort requires explicit --expect-generation/--expect-counter/--expect-image")
    if args.operation != "abort" and any(value is not None for value in guards):
        raise ota.Error("candidate mutation guards are abort-only")
    if (not math.isfinite(args.timeout) or not 0 < args.timeout <= 300
            or not math.isfinite(args.max_clock_skew) or not 0 < args.max_clock_skew <= 3600):
        raise ota.Error("bounded finite timeout/clock skew required")
    if args.operation == "abort":
        ota.full_key(args.expect_image)
        if not 0 < args.expect_generation <= 0xFFFFFFFF or not 0 <= args.expect_counter <= 0xFFFFFFFF:
            raise ota.Error("invalid explicit abort attempt guard")
    args.artifacts.mkdir(mode=0o700, parents=False, exist_ok=False)
    if stat.S_IMODE(args.artifacts.stat().st_mode) != 0o700:
        raise ota.Error("private exclusive artifact directory required")
    manager = None
    try:
        with ota.termination_cleanup(), ota.validated_stock_uart(binding, args.by_id, dtr=args.client_dtr) as stream:
            stock = ota.Stock(ota.Frames(stream, keep_login_pushes=True), binding.sender, expected_name=binding.sender_name)
            with ota.radio_guard(stock, binding, args.artifacts, mode="background"):
                manager = RemoteManagement(stock, binding, args.target_name, args.timeout, max_skew=args.max_clock_skew)
                manager.login()
                result = manager.abort(*guards) if args.operation == "abort" else manager.query(args.operation)
    except (ota.Error, OSError, ValueError, TimeoutError) as exc:
        result = {"outcome": "host-cancelled" if isinstance(exc, ota.Cancelled) else "remote-management-incomplete",
                  "operation": args.operation, "error": str(exc),
                  "abort_dispatched": bool(manager and manager.abort_dispatched),
                  "observations": manager.observations if manager else [],
                  "receiver_abort_confirmed": False, **TRUST}
        ota.private_write(args.artifacts / "result.json", result)
        print(json.dumps(result, sort_keys=True))
        raise
    ota.private_write(args.artifacts / "result.json", result)
    print(json.dumps(result, sort_keys=True))
    if args.operation == "abort" and not result["reply"]["durable_abort_confirmed"]:
        raise ota.Error("remote abort acknowledgement did not revoke candidate; readback saved")


if __name__ == "__main__":
    try:
        main()
    except (ota.Error, OSError, ValueError, TimeoutError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
