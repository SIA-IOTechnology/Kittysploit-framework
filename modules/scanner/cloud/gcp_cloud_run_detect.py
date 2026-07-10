#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Google Cloud Run services."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "GCP Cloud Run Detection",
        "description": "Detects Cloud Run hostnames and Google Frontend trace headers.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["cloud", "scanner", "gcp", "cloud-run", "serverless"],
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
        cloud_run_host = host.endswith(".run.app") or host.endswith(".a.run.app")
        r = self.http_request(method="GET", path="/", allow_redirects=False)
        if not r:
            return False
        headers = {k.lower(): v for k, v in r.headers.items()}
        has_trace = "x-cloud-trace-context" in headers
        server = headers.get("server", "").lower()
        if not cloud_run_host and not (has_trace and "google" in server):
            return False
        if is_html_response(r) and not cloud_run_host and not has_trace:
            return False
        self.set_info(severity="info", reason="GCP Cloud Run service detected", host=host)
        return True
