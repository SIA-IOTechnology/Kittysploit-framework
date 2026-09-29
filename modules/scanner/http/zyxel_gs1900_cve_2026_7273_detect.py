#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Zyxel GS1900 CVE-2026-7273 CGI stack buffer overflow exposure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Zyxel GS1900 CVE-2026-7273 Detect",
        "description": (
            "Detects Zyxel GS1900 smart-managed switches running firmware "
            "2.90(XXXX.1)C0 or earlier, vulnerable to CVE-2026-7273 stack-based "
            "buffer overflow in the web-management CGI program."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-7273"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-7273",
            "https://www.zyxel.com/global/en/support/security-advisories",
        ],
        "tags": [
            "web",
            "scanner",
            "zyxel",
            "gs1900",
            "switch",
            "buffer-overflow",
            "pre-auth",
            "cve-2026-7273",
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
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["zyxel", "gs1900"],
                "endpoint_pattern_any": ["/cgi-bin/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "network_device", "from_detail": "gs1900 cgi"},
                ],
                "suggested_followups": [],
            },
        },
    }

    _FW_RE = re.compile(r"2\.90\([^)]*?\.1\)C0", re.IGNORECASE)
    _PATCHED_RE = re.compile(r"2\.90\([^)]*?\.2\)C0", re.IGNORECASE)

    def _is_gs1900(self) -> tuple[bool, str]:
        for path in ("/", "/login.cgi", "/cgi-bin/login.cgi"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response:
                continue
            body = response.text or ""
            blob = body.lower()
            if "gs1900" in blob or "zyxel" in blob:
                return True, body
        return False, ""

    def _firmware_affected(self, body: str) -> bool | None:
        if self._PATCHED_RE.search(body or ""):
            return False
        if self._FW_RE.search(body or ""):
            return True
        if re.search(r"GS1900", body or "", re.IGNORECASE):
            return None
        return None

    def _cgi_reachable(self) -> bool:
        for path in ("/cgi-bin/dispatcher.cgi", "/cgi-bin/account.cgi"):
            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if response and int(response.status_code or 0) not in (404, 410):
                return True
        return False

    def run(self):
        present, body = self._is_gs1900()
        if not present:
            return False
        affected = self._firmware_affected(body)
        cgi = self._cgi_reachable()
        if affected is False:
            return False
        if affected is True or (cgi and affected is None):
            self.set_info(
                severity="high",
                cve="CVE-2026-7273",
                reason=(
                    "GS1900 firmware appears pre-2.90(x.2)C0 with reachable CGI endpoints"
                    if affected
                    else "GS1900 management CGI reachable (firmware unknown)"
                ),
            )
            return True
        return False
