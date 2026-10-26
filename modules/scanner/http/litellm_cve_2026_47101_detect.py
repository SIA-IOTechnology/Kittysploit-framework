#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fingerprints LiteLLM proxy API (/health, OpenAI-compatible routes)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "LiteLLM CVE-2026-47101 Detect",
        "description": "Fingerprints LiteLLM proxy API (/health, OpenAI-compatible routes).",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-47101"],
        "tags": ["scanner", "web", "litellm", "cve-2026-47101"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-47101"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/litellm_cve_2026_47101_privesc"],
            },
        },
    }
    port = OptPort(4000, "LiteLLM port", required=False)

    def run(self):
        for path in ("/health", "/v1/models", "/"):
            r = self.http_request("GET", path, allow_redirects=False)
            body = (r.text or "").lower() if r else ""
            if "litellm" in body or (r and int(r.status_code or 0) == 200 and "model" in body):
                self.set_info(severity="critical", cve="CVE-2026-47101", reason="LiteLLM API surface", confidence="medium")
                return True
        return False
