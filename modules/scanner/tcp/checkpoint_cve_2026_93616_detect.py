#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Check Point CVE-2026-93616 management server pre-auth path traversal surface."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.tcp.tcp_scanner_client import Tcp_scanner_client


class Module(Scanner, Http_client, Tcp_scanner_client):
    __info__ = {
        "name": "Check Point CVE-2026-93616 Management Detect",
        "description": (
            "Detects exposure to CVE-2026-93616 on Check Point Quantum Security "
            "Management (SmartConsole/SMS) before R82.20 / JHF takes listed in sk1000171. "
            "Fingerprints the management web service on TCP/19009 and reachable HTTPS "
            "management panels without sending exploit upload payloads."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-93616"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-93616",
            "https://support.checkpoint.com/results/sk/sk1000171",
            "https://blog.checkpoint.com/security/security-advisory-action-required-active-exploitation-of-cve-2026-85102-and-a-management-pre-authentication-vulnerability-cve-2026-93616/",
        ],
        "tags": [
            "scanner",
            "tcp",
            "checkpoint",
            "management",
            "path-traversal",
            "cve-2026-93616",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.1,
            "requires": {
                "tech_hints_any": ["checkpoint"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "management upload"},
                ],
                "suggested_followups": [
                    "scanner/http/checkpoint_detect",
                ],
            },
        },
    }

    mgmt_port = OptPort(19009, "Check Point management web service port", True)
    ssl = OptBool(True, "Use HTTPS for management probes", True, advanced=True)

    _BUILD_RE = re.compile(r"(R8[0-9]\.\d+|R81\.\d+)", re.IGNORECASE)

    def _mgmt_open(self) -> bool:
        host = self._host()
        port = int(self.mgmt_port or 19009)
        return bool(host and self.is_tcp_open(host=host, port=port))

    def _mgmt_http(self) -> tuple[bool, str]:
        saved_port = self.port
        saved_ssl = self.ssl
        try:
            self.port = int(self.mgmt_port or 19009)
            self.ssl = bool(self.ssl)
            for path in ("/", "/login", "/smartview/"):
                response = self.http_request(method="GET", path=path, allow_redirects=True)
                if not response:
                    continue
                body = response.text or ""
                headers = " ".join(f"{k}:{v}" for k, v in (response.headers or {}).items())
                blob = f"{headers}\n{body[:8000]}"
                if any(token in blob for token in ("Check Point", "SmartConsole", "cpm", "Gaia")):
                    match = self._BUILD_RE.search(blob)
                    return True, match.group(1) if match else ""
        finally:
            self.port = saved_port
            self.ssl = saved_ssl
        return False, ""

    def run(self):
        if not self._mgmt_open():
            return False
        exposed, build = self._mgmt_http()
        if not exposed:
            self.set_info(
                severity="medium",
                cve="CVE-2026-93616",
                reason="Check Point management TCP/19009 reachable (panel fingerprint inconclusive)",
                port=int(self.mgmt_port or 19009),
            )
            return True
        self.set_info(
            severity="critical",
            cve="CVE-2026-93616",
            reason="Check Point management web service exposed — verify patch level against sk1000171",
            build=build or "unknown",
            port=int(self.mgmt_port or 19009),
        )
        return True
