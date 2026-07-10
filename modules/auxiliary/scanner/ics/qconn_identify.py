#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
QNX qconn service identification (TCP/8000).

Read-only probe for the QNX Neutrino qconn debug service before exploitation.
"""

from __future__ import annotations

from kittysploit import *
from lib.protocols.ics.constants import ICS_PROTOCOL_PORTS
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.qnx.qconn_client import QCONN_DEFAULT_PORT, probe_qconn_service


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "QNX qconn identify",
        "description": (
            "Detects the QNX Neutrino qconn remote debug service on TCP/8000 and "
            "fingerprints launcher availability without spawning a shell."
        ),
        "author": "KittySploit Team",
        "tags": ["ics", "qnx", "qconn", "rtos", "enumeration", "ot"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["credentials"],
                "suggested_followups": ["exploits/ics/qnx/qconn_rce"],
            },
        },
    }

    port = OptPort(QCONN_DEFAULT_PORT, "qconn TCP port", True)

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not self.is_tcp_open(port=self._port()):
            return {"vulnerable": False, "reason": f"TCP {self._port()} closed", "confidence": "high"}
        return {"vulnerable": True, "reason": "qconn port open", "confidence": "low"}

    def run(self):
        host = self._host()
        if not host:
            print_warning("Target is required")
            return False

        print_status(f"Probing QNX qconn at {host}:{self._port()}...")
        probe = probe_qconn_service(host, self._port(), self._timeout())

        if not probe.get("open"):
            print_error(f"TCP {host}:{self._port()} unreachable: {probe.get('error') or 'closed'}")
            return False

        print_success(f"TCP port {self._port()} open on {host}")
        if probe.get("qconn"):
            print_success("qconn service fingerprint matched")
        else:
            print_warning("Port open but qconn banner inconclusive — manual validation recommended")

        if probe.get("banner"):
            print_info(f"Banner excerpt: {str(probe.get('banner'))[:180]}")
        if probe.get("services"):
            print_info(f"Services mentioned: {', '.join(probe.get('services') or [])}")

        self.sync_workspace_ics(
            port=self._port(),
            protocol="qconn",
            vendor="QNX",
            device_type="RTOS / gateway",
            purdue_level=1,
            source="auxiliary/scanner/ics/qconn_identify",
        )
        return True
