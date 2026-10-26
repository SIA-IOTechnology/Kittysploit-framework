#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cacti CVE-2022-46169 remote_agent X-Forwarded-For bypass detect."""

from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Cacti CVE-2022-46169 remote_agent Detect",
        "description": (
            "Detects auth bypass on /remote_agent.php via X-Forwarded-For and "
            "poller_id injection surface."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2022-46169"],
        "tags": ["web", "scanner", "cacti", "cve-2022-46169"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-46169"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/cacti_cve_2022_46169_rce"],
            },
        },
    }

    cacti_path = OptString("", "Cacti URL prefix", required=False)

    def _query(self, poller_id: str, xff: str | None = None) -> str:
        prefix = str(self.cacti_path or "").strip().rstrip("/")
        base = f"{prefix}/remote_agent.php" if prefix else "/remote_agent.php"
        params = (
            f"action=polldata&local_data_ids[0]=6&host_id=1&poller_id="
            f"{quote(poller_id, safe='')}"
        )
        headers = {"X-Forwarded-For": xff} if xff else None
        r = self.http_request("GET", f"{base}?{params}", headers=headers)
        return (r.text or "") if r else ""

    def run(self):
        neg = self._query("1").lower()
        pos = self._query("1", "127.0.0.1")
        if "not authorized" in neg and (pos.strip().startswith("[") or "local_data_id" in pos):
            self.set_info(
                severity="critical",
                cve="CVE-2022-46169",
                reason="remote_agent X-Forwarded-For auth bypass",
                confidence="high",
            )
            return True
        return False
