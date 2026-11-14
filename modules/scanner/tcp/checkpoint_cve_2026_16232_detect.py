#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check Point SmartConsole auth bypass surface (CVE-2026-16232)."""

from kittysploit import *
from lib.protocols.tcp.checkpoint_cpmi import FWM_PORT, cpmi_bind_check
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "Check Point CVE-2026-16232 SmartConsole Detect",
        "description": (
            "Probes TCP/18190 FWM/CPMI for the forged application certificate bind "
            "used in CVE-2026-16232 (SmartConsole SSO bypass on SMS/MDS)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-16232"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-16232",
            "https://support.checkpoint.com/results/sk/sk185169",
        ],
        "tags": ["checkpoint", "scanner", "tcp", "smartconsole", "cve-2026-16232"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/linux/misc/checkpoint_cve_2026_16232_smartconsole_rce",
                ],
            },
        },
    }

    fwm_port = OptPort(FWM_PORT, "FWM/CPMI service port", True)
    timeout = OptInteger(12, "Socket timeout for CPMI probe", required=False, advanced=True)

    def run(self):
        host = self._host()
        if not host:
            return False
        port = int(self.fwm_port or FWM_PORT)
        if not self.is_tcp_open(host=host, port=port):
            return False
        vulnerable, detail = cpmi_bind_check(host, fwm_port=port, timeout=float(self.timeout or 12))
        if vulnerable:
            self.set_info(
                severity="critical",
                cve="CVE-2026-16232",
                reason=f"CPMI application bind accepted SIC DN {detail[:80]}",
                port=port,
            )
            return True
        if detail and "connection" in detail.lower():
            self.set_info(severity="info", reason=detail, port=port)
        return False