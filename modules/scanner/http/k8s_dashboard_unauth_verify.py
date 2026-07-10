#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify Kubernetes Dashboard skip-login and API proxy exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Kubernetes Dashboard Unauth Verification",
        "description": "Confirms Kubernetes Dashboard settings allowing skip-login or open proxy API.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": ["kubernetes", "k8s", "dashboard", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["k8s_misconfig", "admin_surface"]},
        },
    }

    def run(self):
        for path in (
            "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/api/v1/namespaces",
            "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/api/v1/namespaces",
            "/settings",
        ):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if not err and isinstance(data, dict) and data.get("items") is not None:
                self.set_info(
                    severity="critical",
                    reason="Kubernetes Dashboard proxy exposes namespaced API without auth",
                    path=path,
                    confidence="high",
                )
                return True
            if r and r.status_code == 200 and "enableSkipLogin" in (r.text or ""):
                self.set_info(
                    severity="critical",
                    reason="Kubernetes Dashboard skip-login setting enabled",
                    confidence="high",
                )
                return True
        return False
