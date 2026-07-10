#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify unauthenticated kubelet read-only API on port 10255."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Kubelet Read-Only API Verification",
        "description": "Confirms anonymous /pods access on kubelet read-only port 10255.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": ["cloud", "kubernetes", "kubelet", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["k8s_misconfig", "unauth_read"]},
        },
    }

    port = OptPort(10255, "Kubelet read-only port", True)
    ssl = OptBool(False, "Use HTTPS", required=False)

    def run(self):
        for path in ("/pods", "/metrics", "/stats/summary"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            data, err = parse_json_response(r) if path in ("/pods", "/stats/summary") else (None, "skip")
            if not err and isinstance(data, dict) and data.get("items") is not None:
                self.set_info(
                    severity="critical",
                    reason="Kubelet read-only API exposes pod list without authentication",
                    path=path,
                    pod_count=len(data.get("items") or []),
                    confidence="high",
                )
                return True
            if path == "/metrics" and "kubelet" in (r.text or "").lower():
                self.set_info(
                    severity="high",
                    reason="Kubelet metrics endpoint readable without authentication",
                    path=path,
                    confidence="high",
                )
                return True
        return False
