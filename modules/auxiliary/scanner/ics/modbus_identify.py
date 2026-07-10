#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.modbus_client import identify_modbus_device


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "Modbus TCP identify",
        "description": (
            "Actively probes Modbus TCP (port 502) by scanning unit IDs and reading "
            "holding registers. Safe read-only reconnaissance for PLC/RTU discovery."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "modbus", "scada", "ot", "enumeration"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["credentials"],
                "suggested_followups": [
                    "scanner/ics/modbus_write_enabled",
                    "post/ics/modbus/gather/map_registers",
                ],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["modbus-tcp"], "Modbus TCP port", True)
    unit_start = OptInteger(1, "First Modbus unit ID to scan", False)
    unit_end = OptInteger(32, "Last Modbus unit ID to scan", False)
    register_address = OptInteger(0, "Register address used for probe reads", False, advanced=True)
    register_count = OptInteger(1, "Number of registers to read per unit", False, advanced=True)

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not self.is_tcp_open():
            return {"vulnerable": False, "reason": f"TCP {self._port()} closed", "confidence": "high"}
        return {"vulnerable": True, "reason": f"Modbus TCP port {self._port()} open", "confidence": "low"}

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        print_status(f"Scanning Modbus TCP on {host}:{self._port()}...")
        result = identify_modbus_device(
            host,
            self._port(),
            self._timeout(),
            int(self.unit_start or 1),
            int(self.unit_end or 32),
        )

        if not result.get("reachable"):
            print_error(f"Could not connect to {host}:{self._port()}")
            return False

        units = result.get("units") or []
        if not units:
            print_warning("Modbus TCP reachable but no responsive unit IDs found in range")
            return False

        print_success(f"Modbus TCP device(s) on {host}:{self._port()}")
        unit_ids = []
        for unit in units:
            regs = unit.get("registers") or []
            preview = ", ".join(str(v) for v in regs[:8]) if regs else "n/a"
            print_info(f"  unit_id={unit.get('unit_id')} registers=[{preview}]")
            if unit.get("unit_id") is not None:
                unit_ids.append(int(unit["unit_id"]))
        self.sync_workspace_ics(
            port=self._port(),
            protocol="modbus-tcp",
            modbus_units=unit_ids,
            device_type="PLC/RTU",
            purdue_level=1,
            source="auxiliary/scanner/ics/modbus_identify",
        )
        return True
