#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect FTP FEAT capabilities (TLS, UTF8, EPSV, …)."""

from kittysploit import *
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client
from lib.scanner.ftp.detectors import probe_ftp_feat


class Module(Scanner, Tcp_scanner_client):
    __info__ = {
        "name": "FTP FEAT Detection",
        "description": "Lists FTP features advertised via FEAT (AUTH TLS, UTF8, EPSV, …).",
        "author": ["KittySploit Team"],
        "severity": "info",
        "references": ["https://datatracker.ietf.org/doc/html/rfc2389"],
        "tags": ["ftp", "network", "scanner", "enum", "discovery", "tls"],
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
        info = probe_ftp_feat(host=host, port=port, timeout=self._timeout())
        if not info.get("detected"):
            return False
        features = [str(f) for f in (info.get("features") or []) if f]
        if not features:
            return False
        banner = str(info.get("banner") or "").strip()
        tls = any(f.startswith("AUTH") or f in ("PBSZ", "PROT") for f in features)
        severity = "info"
        reason = f"FTP FEAT: {', '.join(features)}"
        if not tls:
            severity = "low"
            reason = f"{reason} | no AUTH TLS advertised"
        if banner:
            reason = f"{reason} | banner={banner}"
        self.set_info(
            severity=severity,
            reason=reason,
            features=features,
            tls_advertised=tls,
            banner=banner,
        )
        return True
