#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.s7_client import identify_s7_device, snap7_available


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "S7comm identify",
        "description": (
            "Connects to Siemens S7 PLCs over ISO-on-TCP (port 102) and reads CPU / "
            "module identification plus protection level via SZL."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "siemens", "s7comm", "scada", "plc", "enumeration"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["credentials"],
                "suggested_followups": [
                    "auxiliary/scanner/ics/s7comm_session_acquire",
                    "scanner/ics/s7_protection_level",
                ],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["s7comm"], "S7comm / ISO-on-TCP port", True)
    rack = OptInteger(0, "PLC rack number", False)
    slot = OptInteger(1, "PLC slot number", False)
    password = OptString("", "Optional S7 session password", False)

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not self.is_tcp_open():
            return {"vulnerable": False, "reason": "TCP 102 closed", "confidence": "high"}
        return {"vulnerable": True, "reason": "S7comm port open", "confidence": "low"}

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        if snap7_available():
            print_info("Using python-snap7 backend when available")
        else:
            print_info("python-snap7 not installed — using built-in ISO-on-TCP client")

        print_status(f"Identifying Siemens S7 at {host}:{self._port()} (rack={self.rack}, slot={self.slot})...")
        identity = identify_s7_device(
            host,
            self._port(),
            self._timeout(),
            int(self.rack or 0),
            int(self.slot or 1),
            str(self.password or ""),
        )

        if not identity.connected:
            print_error(f"S7comm connection failed: {identity.error or 'unknown error'}")
            return False

        print_success(f"S7comm reachable on {host}:{self._port()} ({identity.backend})")
        if identity.module_type_name:
            print_info(f"  Module: {identity.module_type_name}")
        if identity.serial_number:
            print_info(f"  Serial: {identity.serial_number}")
        if identity.firmware:
            print_info(f"  Firmware: {identity.firmware}")
        print_info(f"  Protection: {identity.protection_label} (level {identity.protection_level})")

        if identity.protection_level == 1:
            print_warning("PLC reports protection level 1 (no password protection)")

        self.sync_workspace_ics(
            port=self._port(),
            protocol="s7comm",
            vendor="Siemens",
            device_type=identity.module_type_name or "PLC/RTU",
            purdue_level=1,
            s7_slot=int(self.slot or 1),
            protection_level=int(identity.protection_level or 0),
            source="auxiliary/scanner/ics/s7comm_identify",
        )
        return True
