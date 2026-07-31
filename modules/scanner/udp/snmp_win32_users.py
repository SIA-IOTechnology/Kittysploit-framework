#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windows users via SNMP (NSE snmp-win32-users)."""

from kittysploit import *
from lib.scanner.snmp.detectors import probe_snmp_win32_users


class Module(Scanner):
    __info__ = {
        "name": "SNMP Win32 Users",
        "description": (
            "Enumerates Windows local usernames via LANMANAGER-MIB over SNMP "
            "(NSE snmp-win32-users)."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": ["https://nmap.org/nsedoc/scripts/snmp-win32-users.html"],
        "tags": ["snmp", "windows", "users", "udp", "scanner", "enum"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 10,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    target = OptString("", "Target hostname or IP", True)
    port = OptPort(161, "SNMP UDP port", True)
    community = OptString("public", "SNMP community", False)
    timeout = OptPort(5, "Timeout seconds", False, advanced=True)

    def run(self):
        host = str(self.target or "").strip()
        if not host:
            return False
        info = probe_snmp_win32_users(
            host=host,
            community=str(self.community or "public"),
            port=int(self.port or 161),
            timeout=float(self.timeout or 5),
        )
        if not info.get("detected"):
            return False
        users = info.get("users") or []
        self.set_info(
            severity="medium",
            reason=f"SNMP disclosed {len(users)} Windows user(s)",
            users=list(users)[:40],
        )
        return True
