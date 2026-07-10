#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Apache Airflow web UI and health API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache Airflow Detection",
        "description": "Detects Airflow /api/v1/health and admin UI.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "airflow", "apache", "workflow", "panel"],
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
        for path in ("/api/v1/health", "/health", "/api/v2/version"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if err or not data:
                continue
            if "metadatabase" in data or "scheduler" in data or "version" in data:
                self.set_info(severity="medium", reason="Apache Airflow API detected", path=path)
                return True
        return False
