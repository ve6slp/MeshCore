import argparse
import contextlib
from enum import Enum
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import swd_diagnose as swd


class State(Enum):
    RUNNING = 1
    HALTED = 2
    SLEEPING = 3
    LOCKUP = 4
    RESET = 5


class Sequence:
    def __init__(self, *tasks):
        self.tasks = dict(tasks)

    def remove_task(self, name):
        del self.tasks[name]
        return self

    def replace_task(self, name, replacement):
        if name not in self.tasks:
            raise KeyError(name)
        self.tasks[name] = replacement
        return self

    def insert_before(self, before, task):
        tasks = {}
        for name, function in self.tasks.items():
            if name == before:
                tasks[task[0]] = task[1]
            tasks[name] = function
        self.tasks = tasks
        return self

    def wrap_task(self, name, wrapper):
        original = self.tasks[name]
        self.tasks[name] = lambda: wrapper(original())

    def invoke(self):
        for function in self.tasks.values():
            nested = function()
            if isinstance(nested, Sequence):
                nested.invoke()


class FakeTarget:
    def __init__(self, events, serial=swd.APPROVED_SERIAL, locked=False, state=State.RUNNING,
                 debug_enabled=None):
        self.events = events
        self.state = state
        self.fail_address = None
        self.fail_register = None
        self.fail_halt = False
        self.fail_resume = False
        self.resume_state = State.RUNNING
        self.resume_stays_halted = False
        self.debug_enabled = state == State.HALTED if debug_enabled is None else debug_enabled
        self.fail_debug_write = False
        self.ignore_debug_write = False
        self.dhcsr_reads = 0
        self.fail_dhcsr_read = None
        self.ctrl_ap = SimpleNamespace(idr=0x02880000, read_reg=self.security)
        self.locked = locked
        self.aps = {0: self, 1: self.ctrl_ap}
        self.memory = {
            0x10000060: int(serial[8:], 16), 0x10000064: int(serial[:8], 16),
            0x10000100: 0x52840, 0x10000104: 0x41414430, 0x10000108: 0x2004,
            8: 0x00001235, 0xFF8: 0xFFFFFFFF, 0xFFC: 0xFFFFFFFF,
            0x10001014: 0xF4000, 0x10001018: 0xFE000,
            0xF4000: 0x20040000, 0xF4004: 0xF4101,
            0x40010400: 0, 0x4001050C: 0, 0x40010504: 32768,
            0x40000400: 1, 0x4000051C: 0x57, 0x20007F7C: 0x4EE5677E,
            0xE000EDFC: 0x01000000,
        }

    def forbidden(self):
        raise AssertionError("unlock/reset/erase/flash/component initialization was invoked")

    reset = mass_erase = write_memory = write_uicr = forbidden

    def write32(self, address, value):
        if address != swd.DHCSR or value != swd.DBGKEY:
            raise AssertionError("only the exact DHCSR debug-disable restore write is permitted")
        if self.state not in (State.RUNNING, State.SLEEPING):
            raise AssertionError("DHCSR clear may not force resume")
        self.events.append(("write32", address, value))
        if self.fail_debug_write:
            raise OSError("debug-enable restore write failed")
        if not self.ignore_debug_write:
            self.debug_enabled = False

    def flush(self):
        pass

    def security(self, address):
        if address != 0xC:
            raise AssertionError("non-security CTRL-AP read")
        self.events.append(("approtect_read", address))
        return 0 if self.locked else 1

    def discovery(self):
        return Sequence(
            ("find_aps", lambda: None), ("create_aps", lambda: None),
            ("check_ctrl_ap_idr", lambda: None), ("check_flash_security", self.forbidden),
            ("find_components", lambda: self.events.append("find_components")),
            ("create_cores", self.create_core),
            ("check_part_info", self.forbidden), ("persist_unlock", self.forbidden),
            ("create_components", self.forbidden),
        )

    def create_core(self):
        if not self.delegate.start_debug_core(self):
            self.forbidden()
        self.events.append("create_cores")

    def initialize(self, delegate):
        self.delegate = delegate
        sequence = Sequence(
            ("load_svd", self.forbidden), ("pre_connect", lambda: None),
            ("dp_init", lambda: None), ("unlock_device", self.forbidden),
            ("discovery", self.discovery), ("halt_on_connect", lambda: None),
            ("create_flash", self.forbidden),
        )
        delegate.will_init_target(self, sequence)
        sequence.invoke()

    def read32(self, address):
        self.events.append(("read32", address))
        if address == self.fail_address:
            raise OSError("read failed")
        if address == swd.DHCSR:
            self.dhcsr_reads += 1
            if self.dhcsr_reads == self.fail_dhcsr_read:
                raise OSError("DHCSR read failed")
            status = {State.HALTED: 1 << 17, State.SLEEPING: 1 << 18,
                      State.LOCKUP: 1 << 19, State.RESET: 1 << 25}.get(self.state, 0)
            return status | int(self.debug_enabled)
        return self.memory.get(address, 0xFFFFFFFF)

    def get_state(self):
        return self.state

    def halt(self):
        self.events.append("halt")
        self.state = State.HALTED
        self.debug_enabled = True
        if self.fail_halt:
            raise OSError("halt transport failed after halting")

    def resume(self):
        self.events.append("resume")
        if self.fail_resume:
            raise OSError("resume failed")
        if not self.resume_stays_halted:
            self.state = self.resume_state

    def read_core_register_raw(self, name):
        self.events.append(("register", name))
        if self.state != State.HALTED or name not in swd.CPU_REGISTERS:
            raise AssertionError("unapproved register read or running CPU")
        if name == self.fail_register:
            raise OSError("register read failed")
        return 0xF4123 if name == "pc" else 0

    def disconnect(self, resume):
        if resume is not False:
            raise AssertionError("disconnect may not resume a preexisting halted CPU")
        self.events.append("detach_without_resume")
        self.debug_enable_after_detach = self.debug_enabled


class DiagnosisTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.target = FakeTarget(self.events)
        self.probe = SimpleNamespace(
            unique_id="full-probe-uid", vendor_name="Raspberry Pi", product_name="Debug Probe",
            is_open=False, disconnect=lambda: self.events.append("probe_disconnect"),
            close=self.close_probe,
        )
        self.probes = [self.probe]
        self.args = argparse.Namespace(
            role="target", target_serial=swd.APPROVED_SERIAL, probe_uid=self.probe.unique_id,
            config=swd.ROOT / "lab" / "devices.ini",
        )
        self.inventory = """[roles]
client = 4186AE911D94CDB1
target = 77CD44653A967172
[recovery]
target = 3BE94917B92DC5E9
[protected]
pine = 49C5BAF21EEF44A1
"""
        mock.patch.object(Path, "open", side_effect=lambda: io.StringIO(self.inventory)).start()
        self.session = None
        outer = self

        class FakeSession:
            def __init__(self, probe, auto_open, options):
                outer.events.append(("session", probe.unique_id, auto_open, options))
                self.probe = probe
                self.target = outer.target
                self.options = options
                self.delegate = None
                outer.session = self

            def open(self):
                outer.events.append("open")
                self.probe.is_open = True
                self.target.initialize(self.delegate)

        self.select = mock.Mock(side_effect=lambda **kwargs: self.probes)
        self.api = SimpleNamespace(Session=FakeSession, State=State, NRF52840=FakeTarget,
                                   Probe=SimpleNamespace(get_all_connected_probes=self.select))
        self.loader = mock.patch.object(swd, "load_pyocd", return_value=self.api).start()
        self.addCleanup(mock.patch.stopall)

    def close_probe(self):
        self.events.append("probe_close")
        self.probe.is_open = False
        self.target.debug_enable_after_close = self.target.debug_enabled

    def run_diagnosis(self):
        return swd.diagnose(self.args)

    def assert_no_execution_control(self):
        self.assertNotIn("halt", self.events)
        self.assertNotIn("resume", self.events)

    def test_success_uses_exact_probe_and_safe_attach_options(self):
        result = self.run_diagnosis()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "acquired_not_installation_proof")
        self.select.assert_called_once_with(unique_id="full-probe-uid", is_explicit=True)
        _, uid, auto_open, options = next(e for e in self.events if isinstance(e, tuple) and e[0] == "session")
        self.assertEqual(uid, "full-probe-uid")
        self.assertIs(auto_open, False)
        for name, value in (("target_override", "nrf52840"), ("connect_mode", "attach"),
                            ("auto_unlock", False), ("resume_on_disconnect", False),
                            ("no_config", True), ("pack", None), ("cbuild_run", None)):
            self.assertEqual(options[name], value)
        self.assertEqual(result["identity"]["observed_serial"], swd.APPROVED_SERIAL)
        self.assertEqual(result["identity"]["deviceid"], ["0xB92DC5E9", "0x3BE94917"])
        self.assertEqual(result["identity"]["part"], "0x00052840")
        self.assertEqual(result["actual_addresses"], result["expected_addresses"])
        self.assertEqual(set(result["cpu"]["registers"]), set(swd.CPU_REGISTERS))
        self.assertEqual(result["cpu"]["original_state"], "RUNNING")
        self.assertEqual(result["cpu"]["final_state"], "RUNNING")
        self.assertTrue(result["cpu"]["state_restored"])
        self.assertIs(result["cpu"]["original_debug_enabled"], False)
        self.assertIs(result["cpu"]["final_debug_enabled"], False)
        self.assertTrue(result["cpu"]["debug_enable_restored"])
        self.assertIs(self.target.debug_enable_after_detach, False)
        self.assertIs(self.target.debug_enable_after_close, False)
        self.assertEqual(self.target.memory[0xE000EDFC], 0x01000000)
        self.assertEqual(result["watchdog"], {"runstatus": "0x00000000", "config": "0x00000000",
                                            "crv": "0x00008000", "running": False,
                                            "halt_behavior": "pause"})
        self.assertEqual(result["boot_metadata"], {"resetreas": "0x00000001", "gpregret": "0x00000057",
                                                  "double_reset_word": "0x4EE5677E"})
        self.assertEqual(self.events[-3:], ["detach_without_resume", "probe_disconnect", "probe_close"])
        self.assertLess(self.events.index(("read32", 0x10000064)), self.events.index("create_cores"))
        self.assertLess(self.events.index(("read32", 0xE000ED30)), self.events.index("halt"))
        self.assertEqual(result["errors"], [])
        self.assertIsNotNone(result["started_at"])
        self.assertIsNotNone(result["completed_at"])

    def test_attach_core_debug_enable_rewrite_is_explicitly_suppressed(self):
        result = self.run_diagnosis()
        self.assertTrue(result["ok"])
        self.assertIs(self.session.delegate.start_debug_core(self.target), True)

    def test_mbr_boot_word_is_ff8_not_realistic_nmi_vector_at_8(self):
        self.assertEqual(self.target.memory[8], 0x1235)
        result = self.run_diagnosis()
        self.assertTrue(result["ok"])
        self.assertEqual(result["actual_addresses"]["mbr_boot"], "0xFFFFFFFF")
        self.assertIn(("read32", 0xFF8), self.events)
        self.assertNotIn(("read32", 8), self.events)

    def test_runnable_states_allow_sleep_or_spurious_wake_and_restore_original_debug_enable(self):
        for original in (State.RUNNING, State.SLEEPING):
            for final in (State.RUNNING, State.SLEEPING):
                for enabled in (False, True):
                    with self.subTest(original=original, final=final, enabled=enabled):
                        self.events.clear()
                        self.target = FakeTarget(self.events, state=original, debug_enabled=enabled)
                        self.target.resume_state = final
                        result = self.run_diagnosis()
                        self.assertTrue(result["ok"], result)
                        self.assertEqual(result["cpu"]["original_state"], original.name)
                        self.assertEqual(result["cpu"]["final_state"], final.name)
                        self.assertTrue(result["cpu"]["state_restored"])
                        self.assertEqual(result["cpu"]["original_debug_enabled"], enabled)
                        self.assertEqual(result["cpu"]["final_debug_enabled"], enabled)
                        self.assertTrue(result["cpu"]["debug_enable_restored"])
                        self.assertEqual(self.target.debug_enable_after_detach, enabled)
                        self.assertEqual(self.target.debug_enable_after_close, enabled)
                        writes = [e for e in self.events if isinstance(e, tuple) and e[0] == "write32"]
                        self.assertEqual(writes, [] if enabled else [("write32", swd.DHCSR, swd.DBGKEY)])
                        self.assertEqual(self.target.memory[0xE000EDFC], 0x01000000)

    def test_failed_or_noop_normal_resume_never_uses_dhcsr_clear_to_force_resume(self):
        for original in (State.RUNNING, State.SLEEPING):
            for failure in ("exception", "noop"):
                with self.subTest(original=original, failure=failure):
                    self.events.clear()
                    self.target = FakeTarget(self.events, state=original)
                    self.target.fail_resume = failure == "exception"
                    self.target.resume_stays_halted = failure == "noop"
                    result = self.run_diagnosis()
                    self.assertFalse(result["ok"])
                    self.assertEqual(result["cpu"]["final_state"], "HALTED")
                    self.assertFalse(result["cpu"]["state_restored"])
                    self.assertIs(result["cpu"]["final_debug_enabled"], True)
                    self.assertFalse(result["cpu"]["debug_enable_restored"])
                    self.assertIs(self.target.debug_enable_after_close, True)
                    self.assertIn("state_restore", [e["phase"] for e in result["errors"]])
                    self.assertFalse(any(isinstance(e, tuple) and e[0] == "write32" for e in self.events))

    def test_debug_enable_restore_write_failure_or_readback_mismatch_is_explicit_failure(self):
        for failure in ("write", "readback"):
            with self.subTest(failure=failure):
                self.events.clear()
                self.target = FakeTarget(self.events)
                self.target.fail_debug_write = failure == "write"
                self.target.ignore_debug_write = failure == "readback"
                result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertTrue(result["cpu"]["state_restored"])
                self.assertIs(result["cpu"]["final_debug_enabled"], True)
                self.assertFalse(result["cpu"]["debug_enable_restored"])
                self.assertIs(self.target.debug_enable_after_close, True)
                self.assertIn("debug_enable_restore", [e["phase"] for e in result["errors"]])

    def test_original_dhcsr_read_failure_prevents_halt_and_reports_unverified_debug_state(self):
        self.target.fail_dhcsr_read = 1
        result = self.run_diagnosis()
        self.assertFalse(result["ok"])
        self.assertEqual(result["errors"][0], {"phase": "readout", "message": "DHCSR read failed"})
        self.assertIsNone(result["cpu"]["original_debug_enabled"])
        self.assertFalse(result["cpu"]["debug_enable_restored"])
        self.assert_no_execution_control()

    def test_final_dhcsr_read_failure_cannot_claim_debug_enable_restoration(self):
        self.target.fail_dhcsr_read = 2
        result = self.run_diagnosis()
        self.assertFalse(result["ok"])
        self.assertTrue(result["cpu"]["state_restored"])
        self.assertIsNone(result["cpu"]["final_debug_enabled"])
        self.assertFalse(result["cpu"]["debug_enable_restored"])
        self.assertIs(self.target.debug_enable_after_close, False)
        self.assertEqual(result["errors"][0], {"phase": "debug_enable_restore", "message": "DHCSR read failed"})

    def test_every_acquisition_read_is_bounded_public_word(self):
        result = self.run_diagnosis()
        self.assertTrue(result["ok"])
        addresses = [e[1] for e in self.events if isinstance(e, tuple) and e[0] == "read32"]
        self.assertEqual(set(addresses), swd.PUBLIC_WORDS | {0xF4000, 0xF4004})
        self.assertEqual(addresses.count(swd.DHCSR), 2)
        self.assertEqual(len(addresses), len(set(addresses)) + 1)
        self.assertNotIn(8, addresses)
        self.assertNotIn(0xFF01C, addresses)
        self.assertTrue(all(not 0xD4000 <= a < 0xF4000 for a in addresses))
        self.assertTrue(all(not 0x12000000 <= a < 0x16000000 for a in addresses))

    def test_mismatched_protected_or_healthy_identity_never_halts_or_creates_cores(self):
        for serial in ("49C5BAF21EEF44A1", "4186AE911D94CDB1", "77CD44653A967172"):
            with self.subTest(serial=serial):
                self.events.clear()
                self.target = FakeTarget(self.events, serial=serial)
                result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertEqual(result["identity"]["observed_serial"], serial)
                self.assertIn("identity mismatch", result["errors"][0]["message"])
                self.assertNotIn("create_cores", self.events)
                self.assert_no_execution_control()
                self.assertEqual([r["address"] for r in result["reads"]],
                                 ["0x10000060", "0x10000064", "0x10000100"])

    def test_wrong_chip_part_refuses_before_core_creation(self):
        self.target.memory[0x10000100] = 0x52832
        result = self.run_diagnosis()
        self.assertFalse(result["ok"])
        self.assertNotIn("create_cores", self.events)
        self.assert_no_execution_control()

    def test_approtect_refuses_before_any_system_memory_access(self):
        self.target.locked = True
        result = self.run_diagnosis()
        self.assertFalse(result["ok"])
        self.assertIn("APPROTECT", result["errors"][0]["message"])
        self.assertEqual(result["reads"], [])
        self.assertNotIn("create_cores", self.events)
        self.assert_no_execution_control()

    def test_missing_or_unexpected_debug_ap_refuses_clearly_without_memory_or_execution(self):
        for missing, bad_idr in ((1, False), (0, False), (None, True)):
            with self.subTest(missing=missing, bad_idr=bad_idr):
                self.events.clear()
                self.target = FakeTarget(self.events)
                if missing is not None:
                    del self.target.aps[missing]
                if bad_idr:
                    self.target.ctrl_ap.idr = 0
                result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertEqual(result["reads"], [])
                self.assertIn("AP", result["errors"][0]["message"])
                self.assert_no_execution_control()

    def test_exact_sdk_header_reference_layout_is_reported_without_image_attestation(self):
        sdk = [0x12340001, 0x000000FF, 0x12340, 0x27000, 0xA000, 0x12340, 0x1000]
        self.target.memory.update({0xFF000 + 4 * i: value for i, value in enumerate(sdk)})
        result = self.run_diagnosis()
        self.assertTrue(result["ok"])
        self.assertEqual(result["sdk_header_reference_layout"], {
            "bank_0_code": 1, "bank_0_crc": 0x1234, "bank_1_code": 0xFF,
            "bank_0_size": 0x12340, "sd_image_size": 0x27000, "bl_image_size": 0xA000,
            "app_image_size": 0x12340, "sd_image_start": "0x00001000",
        })
        self.assertEqual(len([r for r in result["reads"] if r["label"] == "sdk_settings_header"]), 7)
        self.assertNotIn(("read32", 0xFF01C), self.events)
        self.assertEqual(result["status"], "acquired_not_installation_proof")

    def test_watchdog_that_pauses_on_halt_is_reported_without_feeding_or_reconfiguration(self):
        self.target.memory[0x40010400] = 1
        self.target.memory[0x40010504] = 5 * 32768
        result = self.run_diagnosis()
        self.assertTrue(result["ok"])
        self.assertTrue(result["watchdog"]["running"])
        self.assertEqual(result["watchdog"]["halt_behavior"], "pause")
        self.assertEqual(result["watchdog"]["crv"], "0x00028000")
        self.assertEqual(self.target.state, State.RUNNING)
        self.assertEqual(self.events.count("halt"), 1)
        self.assertEqual(self.events.count("resume"), 1)

    def test_watchdog_running_through_halt_refuses_cpu_snapshot_without_changing_state(self):
        for state in (State.RUNNING, State.SLEEPING):
            with self.subTest(state=state):
                self.events.clear()
                self.target = FakeTarget(self.events, state=state)
                self.target.memory[0x40010400] = 1
                self.target.memory[0x4001050C] = 8
                result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertIn("active watchdog", result["errors"][0]["message"])
                self.assertEqual(result["watchdog"]["halt_behavior"], "run")
                self.assertIsNotNone(result["actual_addresses"])
                self.assertEqual(result["cpu"]["final_state"], state.name)
                self.assertTrue(result["cpu"]["state_restored"])
                self.assertTrue(result["cpu"]["debug_enable_restored"])
                self.assert_no_execution_control()

    def test_unrecognized_watchdog_status_refuses_new_halt_without_guessing(self):
        for state in (State.RUNNING, State.SLEEPING):
            with self.subTest(state=state):
                self.events.clear()
                self.target = FakeTarget(self.events, state=state)
                self.target.memory[0x40010400] = 2
                result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertIn("unrecognized watchdog status", result["errors"][0]["message"])
                self.assertEqual(self.target.state, state)
                self.assert_no_execution_control()

    def test_initially_halted_target_stays_halted_on_success_and_read_failure(self):
        for fail_register in (None, "pc"):
            with self.subTest(fail_register=fail_register):
                self.events.clear()
                self.target = FakeTarget(self.events, state=State.HALTED)
                self.target.fail_register = fail_register
                result = self.run_diagnosis()
                self.assertEqual(result["ok"], fail_register is None)
                self.assertEqual(self.target.state, State.HALTED)
                self.assertTrue(result["cpu"]["state_restored"])
                self.assertTrue(result["cpu"]["debug_enable_restored"])
                self.assertIs(self.target.debug_enable_after_close, True)
                self.assertFalse(any(isinstance(e, tuple) and e[0] == "write32" for e in self.events))
                self.assert_no_execution_control()

    def test_running_target_restored_on_register_failure_or_partial_halt_failure(self):
        for state in (State.RUNNING, State.SLEEPING):
            for enabled in (False, True):
                for fail_register, fail_halt in (("pc", False), (None, True)):
                    with self.subTest(state=state, enabled=enabled, failure=(fail_register, fail_halt)):
                        self.events.clear()
                        self.target = FakeTarget(self.events, state=state, debug_enabled=enabled)
                        self.target.resume_state = state
                        self.target.fail_register = fail_register
                        self.target.fail_halt = fail_halt
                        result = self.run_diagnosis()
                        self.assertFalse(result["ok"])
                        self.assertEqual(self.target.state, state)
                        self.assertTrue(result["cpu"]["state_restored"])
                        self.assertTrue(result["cpu"]["debug_enable_restored"])
                        self.assertEqual(self.target.debug_enable_after_close, enabled)
                        self.assertEqual(self.events.count("resume"), 1)

    def test_memory_failure_is_explicit_partial_readout_without_halt(self):
        self.target.fail_address = 0x10001014
        result = self.run_diagnosis()
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "acquisition_failed")
        self.assertEqual(result["errors"][0], {"phase": "readout", "message": "read failed"})
        self.assertIsNone(result["actual_addresses"])
        self.assert_no_execution_control()

    def test_untrusted_boot_pointer_never_reads_filesystems_ram_qspi_or_journals(self):
        for source in (0xFF8, 0x10001014):
            for address in (0xD4000, 0xED000, 0xFE000, 0xFF000, 0x27000,
                            0x20000000, 0x12000000, 0xF4001):
                with self.subTest(source=source, address=address):
                    self.events.clear()
                    self.target = FakeTarget(self.events)
                    self.target.memory[source] = address
                    result = self.run_diagnosis()
                    self.assertFalse(result["ok"])
                    self.assertIsNone(result["boot_vector"])
                    self.assertEqual(result["errors"][0]["phase"], "boot_vector")
                    self.assertEqual(result["errors"][0]["address"], swd.hex32(address))
                    self.assertIn("outside approved boot span", result["errors"][0]["message"])
                    if address not in swd.PUBLIC_WORDS:
                        self.assertNotIn(("read32", address), self.events)
                    self.assertFalse(any(r["label"] in ("boot_msp", "boot_reset_handler") for r in result["reads"]))
                    self.assertEqual(len([r for r in result["reads"] if r["label"] == "sdk_settings_header"]), 7)
                    self.assertIn(("read32", 0xE000ED28), self.events)
                    self.assertIn("watchdog", result)
                    self.assertEqual(set(result["cpu"]["registers"]), set(swd.CPU_REGISTERS))
                    self.assertTrue(result["cpu"]["state_restored"])
                    self.assertTrue(result["cpu"]["debug_enable_restored"])
                    self.assertIs(self.target.debug_enable_after_close, False)

    def test_legal_boot_vector_transport_error_or_non_policy_refusal_is_fatal(self):
        for error in (OSError("legal vector read failed"), swd.Refusal("legal vector read refused")):
            with self.subTest(error=error):
                self.events.clear()
                self.target = FakeTarget(self.events)
                reader = self.target.read32

                def failing_reader(address):
                    if address == 0xF4000:
                        raise error
                    return reader(address)

                with mock.patch.object(self.target, "read32", side_effect=failing_reader):
                    result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertEqual(result["errors"][0]["phase"], "readout")
                self.assertNotIn("boot_vector", [e["phase"] for e in result["errors"]])
                self.assertNotIn("sdk_header_reference_layout", result)
                self.assertNotIn("watchdog", result)
                self.assertNotIn("registers", result["cpu"])
                self.assert_no_execution_control()

    def test_bad_boot_policy_still_captures_cpu_and_metadata_but_cli_returns_nonzero(self):
        self.target.memory[0x10001014] = 0xED000
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = swd.main(["diagnose", "--probe-uid", self.args.probe_uid, "--role", "target",
                             "--target-serial", swd.APPROVED_SERIAL])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertFalse(result["ok"])
        self.assertIsNone(result["boot_vector"])
        self.assertEqual(result["errors"][0]["phase"], "boot_vector")
        self.assertEqual(result["errors"][0]["address"], "0x000ED000")
        self.assertIn("sdk_header_reference_layout", result)
        self.assertIn("watchdog", result)
        self.assertEqual(set(result["cpu"]["registers"]), set(swd.CPU_REGISTERS))
        self.assertNotIn(("read32", 0xED000), self.events)

    def test_absent_duplicate_or_partial_probe_uid_has_no_session_or_fallback(self):
        for probes, uid in (([], "full-probe-uid"), ([self.probe, self.probe], "full-probe-uid"),
                            ([self.probe], "probe-uid")):
            with self.subTest(uid=uid, count=len(probes)):
                self.events.clear()
                self.probes, self.args.probe_uid = probes, uid
                result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertEqual(result["errors"][0]["phase"], "probe_selection")
                self.assertEqual(self.events, [])

    def test_request_refuses_healthy_protected_or_empty_explicit_identity_before_dependency(self):
        for serial, uid in (("4186AE911D94CDB1", "full-probe-uid"),
                            ("77CD44653A967172", "full-probe-uid"),
                            ("49C5BAF21EEF44A1", "full-probe-uid"), (swd.APPROVED_SERIAL, "")):
            with self.subTest(serial=serial):
                self.args.target_serial, self.args.probe_uid = serial, uid
                result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertEqual(result["errors"][0]["phase"], "request")
                self.assertEqual(self.events, [])
                self.assertIsNone(self.session)
        self.loader.assert_not_called()
        self.select.assert_not_called()

    def test_recovery_selects_original_target_despite_active_pair_and_environment_overrides(self):
        with mock.patch.dict("os.environ", {"MESHCORE_LAB_TARGET_SERIAL": "77CD44653A967172",
                                           "MESHCORE_LAB_RECOVERY_TARGET_SERIAL": "77CD44653A967172"}):
            result = self.run_diagnosis()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["identity"]["approved_serial"], "3BE94917B92DC5E9")
        self.assertEqual(result["identity"]["observed_serial"], "3BE94917B92DC5E9")
        self.assertEqual(result["identity"]["role"], "target")
        self.loader.assert_called_once()
        self.select.assert_called_once_with(unique_id="full-probe-uid", is_explicit=True)

    def test_legacy_inventory_without_recovery_accepts_only_original_target(self):
        self.inventory = """[roles]
client = 4186AE911D94CDB1
target = 3BE94917B92DC5E9
[protected]
pine = 49C5BAF21EEF44A1
"""
        result = self.run_diagnosis()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["identity"]["observed_serial"], "3BE94917B92DC5E9")

    def test_missing_or_malformed_recovery_target_never_falls_back_to_legacy_role(self):
        base = self.inventory.replace("target = 77CD44653A967172", "target = 3BE94917B92DC5E9")
        for recovery in ("", "other = 3BE94917B92DC5E9", "target =",
                         "target = 77CD44653A967172", "target = 49C5BAF21EEF44A1",
                         "target = 3be94917b92dc5e9", "target = 3BE94917B92DC5E9-extra",
                         "target = 3BE94917B92DC5E9\ntarget = 77CD44653A967172"):
            with self.subTest(recovery=recovery):
                self.inventory = base.replace("[recovery]\ntarget = 3BE94917B92DC5E9",
                                              "[recovery]\n" + recovery)
                result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertEqual(result["errors"][0]["phase"], "request")
                self.loader.assert_not_called()
                self.select.assert_not_called()
                self.assertEqual(self.events, [])
                self.assertIsNone(self.session)

    def test_recovery_collisions_and_inherited_default_target_refuse_before_dependency(self):
        canonical = self.inventory
        inventories = (
            canonical.replace("target = 77CD44653A967172", "target = 3BE94917B92DC5E9"),
            canonical.replace("client = 4186AE911D94CDB1", "client = 3BE94917B92DC5E9"),
            canonical.replace("pine = 49C5BAF21EEF44A1", "pine = 3BE94917B92DC5E9"),
            canonical.replace("[recovery]", "[recovery]\nother = 3BE94917B92DC5E9"),
            "[DEFAULT]\ntarget = 3BE94917B92DC5E9\n"
            + canonical.replace("[recovery]\ntarget = 3BE94917B92DC5E9", "[recovery]"),
        )
        for inventory in inventories:
            with self.subTest(inventory=inventory):
                self.inventory = inventory
                result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertEqual(result["errors"][0]["phase"], "request")
                self.loader.assert_not_called()
                self.select.assert_not_called()
                self.assertEqual(self.events, [])
                self.assertIsNone(self.session)

    def test_inventory_reassignment_or_protected_alias_refuses_before_dependency(self):
        for inventory in ("[roles]\ntarget = 4186AE911D94CDB1\n",
                          "[roles]\ntarget = 77CD44653A967172\n",
                          f"[roles]\ntarget = {swd.APPROVED_SERIAL}\n[protected]\npine = {swd.APPROVED_SERIAL}\n",
                          f"[roles]\ntarget = {swd.APPROVED_SERIAL}\nclient = {swd.APPROVED_SERIAL}\n"):
            with self.subTest(inventory=inventory), mock.patch.object(Path, "open", return_value=io.StringIO(inventory)):
                self.assertFalse(self.run_diagnosis()["ok"])
        self.loader.assert_not_called()

    def test_locked_up_cpu_is_not_silently_resumed_or_reset(self):
        for state in (State.LOCKUP, State.RESET):
            with self.subTest(state=state):
                self.events.clear()
                self.target = FakeTarget(self.events, state=state)
                result = self.run_diagnosis()
                self.assertFalse(result["ok"])
                self.assertIn(state.name, result["errors"][0]["message"])
                self.assertIsNotNone(result["actual_addresses"])
                self.assert_no_execution_control()

    def test_restore_and_detach_errors_are_failure_not_success(self):
        self.target.fail_resume = True
        self.probe.disconnect = mock.Mock(side_effect=OSError("detach failed"))
        result = self.run_diagnosis()
        self.assertFalse(result["ok"])
        self.assertIn("state_restore", [e["phase"] for e in result["errors"]])
        self.assertIn("debug_enable_restore", [e["phase"] for e in result["errors"]])
        self.assertIn("probe_disconnect", [e["phase"] for e in result["errors"]])
        self.assertIs(result["cpu"]["final_debug_enabled"], True)
        self.assertFalse(result["cpu"]["debug_enable_restored"])
        self.assertFalse(any(isinstance(e, tuple) and e[0] == "write32" for e in self.events))
        self.assertEqual(result["status"], "acquisition_failed")
        self.assertIn("probe_close", self.events)

    def test_cli_json_failure_returns_nonzero_and_contains_identity_errors_timestamp(self):
        self.target.locked = True
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = swd.main(["diagnose", "--probe-uid", self.args.probe_uid, "--role", "target",
                             "--target-serial", swd.APPROVED_SERIAL])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["identity"]["probe_uid"], "full-probe-uid")
        self.assertEqual(result["identity"]["approved_serial"], swd.APPROVED_SERIAL)
        self.assertTrue(result["errors"])
        self.assertTrue(result["completed_at"])

    def test_help_requires_no_optional_dependency_or_device_access(self):
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exc:
            swd.main(["--help"])
        self.assertEqual(exc.exception.code, 0)
        self.loader.assert_not_called()
        self.select.assert_not_called()

    def test_arbitrary_word_read_is_refused_before_backend(self):
        readout = swd.Readout({"reads": []})
        for address in (0xED000, 0x20007F78, 0x20007F80, 0x20008000):
            with self.subTest(address=address), \
                    self.assertRaisesRegex(swd.Refusal, "outside bounded public whitelist"):
                readout.word(self.target, address, "private")
        self.assertEqual(self.events, [])

    def test_unsupported_dependency_refuses_before_probe_selection(self):
        self.loader.side_effect = swd.Refusal("unsupported pyOCD API")
        result = self.run_diagnosis()
        self.assertFalse(result["ok"])
        self.assertEqual(result["errors"][0]["phase"], "api")
        self.select.assert_not_called()

    def test_effective_unsafe_session_option_blocks_open(self):
        original_factory = self.api.Session

        def unsafe_factory(*args, **kwargs):
            session = original_factory(*args, **kwargs)
            session.options["connect_mode"] = "pre-reset"
            return session

        self.api.Session = unsafe_factory
        result = self.run_diagnosis()
        self.assertFalse(result["ok"])
        self.assertIn("unsafe effective", result["errors"][0]["message"])
        self.assertNotIn("open", self.events)
        self.assert_no_execution_control()

    def test_non_qualified_target_class_blocks_open(self):
        self.api.NRF52840 = object
        result = self.run_diagnosis()
        self.assertFalse(result["ok"])
        self.assertIn("not the qualified", result["errors"][0]["message"])
        self.assertNotIn("open", self.events)
        self.assert_no_execution_control()


class SessionFactoryTests(unittest.TestCase):
    def test_factory_blocks_external_config_and_separate_user_script_loader_offline(self):
        external_script = mock.Mock(side_effect=AssertionError("external pyocd user script executed"))

        class FakeSession:
            def __init__(self, probe, auto_open, options):
                if not options["no_config"] or options["pack"] is not None or options["cbuild_run"] is not None:
                    raise AssertionError("external configuration permitted")
                self.options = options
                self._load_user_script()

            def _load_user_script(self):
                external_script()

        package = swd.ROOT / ".tmp" / "fake-pyocd-not-written"
        modules = {
            "pyocd": SimpleNamespace(__file__=str(package / "__init__.py")),
            "pyocd.core.session": SimpleNamespace(Session=FakeSession),
            "pyocd.core.target": SimpleNamespace(Target=SimpleNamespace(State=State)),
            "pyocd.probe.cmsis_dap_probe": SimpleNamespace(CMSISDAPProbe=object),
            "pyocd.target.builtin.target_nRF52840_xxAA": SimpleNamespace(NRF52840=FakeTarget),
        }
        dist = SimpleNamespace(version=swd.PYOCD_VERSION, locate_file=lambda name: package)
        with mock.patch.object(swd.importlib.metadata, "distribution", return_value=dist), \
                mock.patch.dict(sys.modules, modules):
            api = swd.load_pyocd()
            session = api.Session(None, auto_open=False, options=swd.OPTIONS.copy())
        external_script.assert_not_called()
        self.assertIs(api.NRF52840, FakeTarget)
        self.assertEqual(session.options["target_override"], "nrf52840")
        self.assertIs(session.options["no_config"], True)


if __name__ == "__main__":
    unittest.main()
