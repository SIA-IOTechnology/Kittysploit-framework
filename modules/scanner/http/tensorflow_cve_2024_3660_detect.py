#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Heuristic for TensorFlow Serving / model upload APIs."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "TensorFlow CVE-2024-3660 Detect",
        "description": "Heuristic for TensorFlow Serving / model upload APIs.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2024-3660"],
        "tags": ["scanner", "web", "tensorflow", "cve-2024-3660"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3660"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/tensorflow_cve_2024_3660_rce"],
            },
        },
    }

    def run(self):
        for path in ("/v1/models", "/"):
            r = self.http_request("GET", path, allow_redirects=False)
            body = (r.text or "").lower() if r else ""
            if "tensorflow" in body or (r and int(r.status_code or 0) == 200 and "model" in body):
                self.set_info(severity="critical", cve="CVE-2024-3660", reason="TensorFlow model API hint", confidence="low")
                return True
        return False
