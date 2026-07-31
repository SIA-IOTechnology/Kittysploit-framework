#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle SID brute (NSE oracle-sid-brute)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.oracle.detectors import probe_oracle_sid_brute


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Oracle SID Brute",
        "description": (
            "Brute-forces common Oracle SIDs against a TNS listener "
            "(NSE oracle-sid-brute)."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "references": ["https://nmap.org/nsedoc/scripts/oracle-sid-brute.html"],
        "tags": ["oracle", "tns", "sid", "brute", "database", "scanner"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 15,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(1521, "Oracle TNS port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_oracle_sid_brute(host=host, port=port, timeout=self._timeout())
        sids = info.get("valid_sids") or []
        if not sids:
            return False
        self.set_info(
            severity="medium",
            reason=f"Valid Oracle SID(s) found ({len(sids)})",
            sids=list(sids),
        )
        return True
