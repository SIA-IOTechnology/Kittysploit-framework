#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Modbus UDP services on port 502."""

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.scanner.modbus.detectors import probe_modbus_udp


class Module(Scanner, Ics_scanner_client):
    __info__ = {
        "name": "Modbus UDP Detection",
        "description": "Detects Modbus UDP responders via read holding registers probe.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["ics", "modbus", "udp", "scada", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(502, "Modbus UDP port", True)
    unit_id = OptInteger(1, "Modbus unit ID", False)

    def run(self):
        host = self._host()
        if not host:
            return False

        info = probe_modbus_udp(
            host=host,
            port=self._port(),
            unit_id=int(self.unit_id or 1),
            timeout=self._timeout(),
        )
        if not info.get("detected"):
            return False

        self.set_info(
            severity="info",
            reason="Modbus UDP service detected",
            unit_id=int(info.get("unit_id") or 1),
        )
        return True
