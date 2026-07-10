#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.modbus_client import test_modbus_write_enabled


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "Modbus write enabled",
        "description": (
            "Checks whether Modbus TCP writes (FC6) are accepted without authentication "
            "by writing a test value and verifying the register change."
        ),
        "author": "KittySploit Team",
        "severity": "high",
        "tags": ["ics", "modbus", "scada", "misconfiguration", "write"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "consumes_capabilities": ["credentials"],
                "produces_capabilities": ["file_read"],
                "suggested_followups": ["post/ics/manage/modbus_write_register"],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["modbus-tcp"], "Modbus TCP port", True)
    unit_id = OptInteger(1, "Modbus unit ID to test", False)
    register_address = OptInteger(0, "Register address used for the write probe", False)
    test_value = OptInteger(0x00A5, "Test value written to the register", False, advanced=True)

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False

        print_status(
            f"Testing Modbus write on {host}:{self._port()} "
            f"(unit={self.unit_id}, reg={self.register_address})..."
        )
        print_warning("This module performs a real register write on the target")

        result = test_modbus_write_enabled(
            host,
            self._port(),
            self._timeout(),
            int(self.unit_id or 1),
            int(self.register_address or 0),
            int(self.test_value or 0x00A5),
        )

        if not result.get("reachable"):
            self.set_info(severity="info", reason=result.get("reason", "connection failed"))
            print_error("Modbus TCP port unreachable")
            return False

        if result.get("write_enabled"):
            self.set_info(
                severity="high",
                reason=result.get("reason", "Modbus writes accepted"),
                unit_id=result.get("unit_id"),
                address=result.get("address"),
            )
            print_success("Modbus write probe succeeded — unauthenticated writes appear enabled")
            if result.get("restored"):
                print_info("Original register value was restored")
            return True

        self.set_info(severity="info", reason=result.get("reason", "writes not verified"))
        print_info(result.get("reason", "Modbus writes not verified"))
        return False
