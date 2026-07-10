#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Microsoft Azure Functions apps."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Azure Functions Detection",
        "description": "Detects Azure Functions hosts and platform response headers.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["cloud", "scanner", "azure", "functions", "serverless"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    def run(self):
        host = str(self.target or "").lower()
        r = self.http_request(method="GET", path="/", allow_redirects=False)
        if not r:
            return False
        headers = {k.lower(): v for k, v in r.headers.items()}
        azure_markers = (
            "x-ms-request-id" in headers,
            "x-ms-invocation-id" in headers,
            "x-azure-ref" in headers,
            host.endswith(".azurewebsites.net"),
        )
        if not any(azure_markers):
            return False
        if is_html_response(r) and not host.endswith(".azurewebsites.net"):
            return False
        self.set_info(
            severity="info",
            reason="Azure Functions / App Service platform detected",
            host=host,
        )
        return True
