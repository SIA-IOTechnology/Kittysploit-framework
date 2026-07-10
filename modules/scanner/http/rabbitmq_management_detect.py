#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed RabbitMQ management plugin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "RabbitMQ Management Detection",
        "description": "Detects RabbitMQ management UI and overview API.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "rabbitmq", "amqp", "panel"],
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
        for path in ("/api/overview", "/api/whoami", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            body = (r.text or "").lower()
            headers = {k.lower(): v for k, v in r.headers.items()}
            if "rabbitmq" in body or "amqp" in body or "rabbitmq" in headers.get("server", ""):
                severity = "high" if path.startswith("/api/") and r.status_code == 200 else "medium"
                self.set_info(severity=severity, reason="RabbitMQ management interface detected", path=path)
                return True
        return False
