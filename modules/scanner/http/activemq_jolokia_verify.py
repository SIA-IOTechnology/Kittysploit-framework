#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify ActiveMQ Jolokia read access without authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ActiveMQ Jolokia Verification",
        "description": "Confirms unauthenticated Jolokia list/read on ActiveMQ web console.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["activemq", "jolokia", "java", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["java_vuln_signal", "unauth_read"]},
        },
    }

    port = OptPort(8161, "ActiveMQ web port", True)

    def run(self):
        for path in ("/api/jolokia/?maxObjects=5", "/api/jolokia/read/java.lang:type=Runtime"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if err or not isinstance(data, dict):
                continue
            if data.get("value") is not None or data.get("request") or data.get("status") == 200:
                self.set_info(
                    severity="high",
                    reason="ActiveMQ Jolokia API readable without authentication",
                    path=path,
                    confidence="high",
                )
                return True
        return False
