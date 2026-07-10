#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed CouchDB/Fauxton endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "CouchDB Detection",
        "description": "Detects CouchDB REST API and Fauxton UI exposure.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "couchdb", "database", "nosql"],
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
        for path in ("/", "/_all_dbs", "/_utils/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401):
                continue
            body = (r.text or "").lower()
            headers = {k.lower(): v for k, v in r.headers.items()}
            if "couchdb" in headers.get("server", "") or "couchdb" in body or "fauxton" in body:
                severity = "high" if path == "/_all_dbs" and r.status_code == 200 else "medium"
                self.set_info(severity=severity, reason="CouchDB detected", path=path)
                return True
        return False
