#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed etcd key-value API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "etcd Detection",
        "description": "Detects unauthenticated etcd v2/v3 health and version endpoints.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "etcd", "kubernetes", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    def run(self):
        for path in ("/health", "/version", "/v2/keys/", "/v3/maintenance/status"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401):
                continue
            body = (r.text or "").lower()
            if "etcd" in body or "raft" in body or "cluster_id" in body:
                severity = "high" if r.status_code == 200 and path.startswith("/v") else "medium"
                self.set_info(severity=severity, reason="etcd API detected", path=path)
                return True
        return False
