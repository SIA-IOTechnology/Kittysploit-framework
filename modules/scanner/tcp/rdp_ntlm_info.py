#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RDP NTLM info via CredSSP (NSE rdp-ntlm-info)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.rdp.detectors import probe_rdp_ntlm_info


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "RDP NTLM Info",
        "description": (
            "Negotiates RDP NLA/CredSSP and parses the NTLM Type-2 challenge for domain / "
            "computer identity (NSE rdp-ntlm-info)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html"],
        "tags": ["rdp", "ntlm", "nla", "windows", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(3389, "RDP port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_rdp_ntlm_info(host=host, port=port, timeout=max(self._timeout(), 8.0))
        if not info.get("detected"):
            return False
        ntlm = info.get("info") or {}
        self.set_info(
            severity="info",
            reason="RDP NTLM challenge disclosed host/domain identity",
            nb_domain=str(ntlm.get("nb_domain") or ""),
            nb_computer=str(ntlm.get("nb_computer") or ""),
            dns_domain=str(ntlm.get("dns_domain") or ""),
            dns_computer=str(ntlm.get("dns_computer") or ""),
            os_version=str(ntlm.get("os_version") or ""),
        )
        return True
