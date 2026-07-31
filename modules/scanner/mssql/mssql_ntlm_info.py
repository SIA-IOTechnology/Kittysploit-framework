#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MSSQL NTLM info (NSE ms-sql-ntlm-info)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.mssql.detectors import probe_mssql_ntlm_info


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "MSSQL NTLM Info",
        "description": (
            "Performs TDS Login7 with NTLM SSPI negotiate and parses the Type-2 challenge "
            "(NSE ms-sql-ntlm-info)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/ms-sql-ntlm-info.html"],
        "tags": ["mssql", "ntlm", "database", "windows", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(1433, "MSSQL port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_mssql_ntlm_info(host=host, port=port, timeout=max(self._timeout(), 8.0))
        if not info.get("detected"):
            return False
        ntlm = info.get("info") or {}
        self.set_info(
            severity="info",
            reason="MSSQL NTLM challenge disclosed host/domain identity",
            nb_domain=str(ntlm.get("nb_domain") or ""),
            nb_computer=str(ntlm.get("nb_computer") or ""),
            dns_domain=str(ntlm.get("dns_domain") or ""),
            dns_computer=str(ntlm.get("dns_computer") or ""),
            os_version=str(ntlm.get("os_version") or ""),
        )
        return True
