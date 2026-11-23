#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-116442 — Dell PowerStore NDMP pre-auth disclosure."""

from kittysploit import *
from lib.protocols.tcp.ndmp_client import Ndmp
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Tcp_scanner_client, Ndmp):
    __info__ = {
        "name": "PowerStore CVE-2026-116442 NDMP detect",
        "description": "Pre-auth CONFIG_GET_SERVER_INFO on TCP 10000.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-116442"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-116442"],
        "tags": ["dell", "powerstore", "ndmp", "cve-2026-116442"],
        "agent": {
            "chain": {
                "suggested_followups": ["auxiliary/scanner/tcp/powerstore_cve_2026_116442_ndmp_probe"],
            },
        },
    }

    port = OptPort(10000, "NDMP TCP port", required=False)

    def run(self):
        status, info, _ = self.ndmp_probe()
        if status not in ("vulnerable", "responded"):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-116442",
            reason=f"NDMP {status}",
            server_info=info,
        )
        return True