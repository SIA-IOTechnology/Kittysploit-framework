#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Apache Tomcat Manager interface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Tomcat Manager Detection",
        "description": "Detects Tomcat /manager/html and host-manager interfaces.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "tomcat", "java", "panel", "misconfig"],
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
        for path in ("/manager/html", "/host-manager/html", "/manager/status"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = (r.text or "").lower()
            auth = headers.get("www-authenticate", "").lower()
            if "tomcat" in auth or "tomcat manager" in body or "manager app" in body:
                severity = "high" if r.status_code == 200 else "medium"
                self.set_info(severity=severity, reason="Tomcat Manager interface detected", path=path)
                return True
        return False
