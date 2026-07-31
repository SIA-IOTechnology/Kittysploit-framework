#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SMTP NTLM challenge info (NSE smtp-ntlm-info)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.ntlm.detectors import probe_smtp_ntlm_info


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "SMTP NTLM Info",
        "description": (
            "Performs SMTP AUTH NTLM negotiate and parses the Type-2 challenge for Windows "
            "domain / computer identity (NSE smtp-ntlm-info)."
        ),
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://nmap.org/nsedoc/scripts/smtp-ntlm-info.html"],
        "tags": ["smtp", "ntlm", "mail", "windows", "scanner", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    port = OptPort(25, "SMTP port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_smtp_ntlm_info(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        ntlm = info.get("info") or {}
        self.set_info(
            severity="info",
            reason="SMTP NTLM challenge disclosed host/domain identity",
            nb_domain=str(ntlm.get("nb_domain") or ""),
            nb_computer=str(ntlm.get("nb_computer") or ""),
            dns_domain=str(ntlm.get("dns_domain") or ""),
            dns_computer=str(ntlm.get("dns_computer") or ""),
            os_version=str(ntlm.get("os_version") or ""),
        )
        return True
