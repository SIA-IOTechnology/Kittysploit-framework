#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Prometheus monitoring endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Prometheus Detection",
        "description": "Detects Prometheus /metrics and status API exposure.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "prometheus", "monitoring", "metrics"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    def run(self):
        for path in ("/metrics", "/api/v1/status/config", "/api/v1/label/__name__/values"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            if path == "/metrics" and ("# HELP" in body or "# TYPE" in body or "prometheus_" in body):
                self.set_info(severity="medium", reason="Prometheus metrics endpoint exposed", path=path)
                return True
            if "prometheus" in body.lower() or "yaml" in body.lower() and path.endswith("config"):
                self.set_info(severity="medium", reason="Prometheus API exposed", path=path)
                return True
        return False
