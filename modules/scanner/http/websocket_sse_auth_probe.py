#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe WebSocket (Socket.io) and SSE endpoints for weak auth and Origin checks."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.websocket_sse_probe import scan_realtime_endpoints


class Module(Scanner, Http_client):
    __info__ = {
        "name": "WebSocket / SSE Auth Probe",
        "description": (
            "Tests Socket.io polling transports, SSE streams, and realtime paths for "
            "unauthenticated access, open CORS, and missing Origin enforcement."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "websocket", "sse", "socket.io", "realtime", "cors"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 12,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.1,
        },
    }

    def run(self):
        findings = scan_realtime_endpoints(self.http_request)
        if not findings:
            return False
        high = [f for f in findings if f.get("severity") == "high"]
        self.set_info(
            severity="high" if high else "medium",
            reason=f"Realtime endpoint exposure ({len(findings)} hit(s))",
            path=findings[0].get("path") or "/socket.io/",
            findings=findings[:12],
        )
        return True
