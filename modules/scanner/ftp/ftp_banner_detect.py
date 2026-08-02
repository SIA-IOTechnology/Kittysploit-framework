#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect FTP service via welcome banner."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.ftp.detectors import probe_ftp_banner


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "FTP Banner Detection",
        "description": "Detects FTP services and fingerprints common server products.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "metadata": {"max-request": 1, "product": "ftp", "vendor": "ietf"},
        "tags": ["ftp", "network", "scanner", "enum", "discovery"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["service_identified", "ftp_surface"],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/ftp/ftp_syst_detect",
                    "scanner/ftp/ftp_feat_detect",
                    "scanner/ftp/ftp_anonymous_login_detect",
                    "auxiliary/scanner/ftp/ftp_enum",
                ],
            },
        },
    }

    port = OptPort(21, "Target FTP port", True)

    def run(self):
        host = self._host()
        port = self._port()
        if not host or not self.is_tcp_open(host=host, port=port):
            return False
        info = probe_ftp_banner(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        product = str(info.get("product") or "unknown")
        banner = str(info.get("banner") or "").strip()
        reason = f"FTP service detected ({product})"
        if banner:
            reason = f"{reason} | banner={banner}"
        self.set_info(
            severity="info",
            reason=reason,
            banner=banner,
            product=product if product != "unknown" else "",
        )
        return True
