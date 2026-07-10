#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed InfluxDB HTTP API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "InfluxDB Detection",
        "description": "Detects InfluxDB ping and health endpoints.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "influxdb", "timeseries", "database"],
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
        for path in ("/ping", "/health", "/query?q=SHOW+DATABASES"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401):
                continue
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = (r.text or "").lower()
            if "x-influxdb" in headers or "influxdb" in body:
                severity = "high" if r.status_code == 200 and "database" in body else "medium"
                self.set_info(severity=severity, reason="InfluxDB API detected", path=path)
                return True
        return False
