#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect MLflow tracking server."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response, is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "MLflow Detection",
        "description": "Detects MLflow tracking server UI and REST API.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "mlflow", "ml", "ai", "panel"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
        },
    }

    port = OptPort(5000, "MLflow default port", True)

    def run(self):
        for path in ("/api/2.0/mlflow/experiments/search", "/ajax-api/2.0/mlflow/experiments/search", "/"):
            r = self.http_request(
                method="POST" if "search" in path else "GET",
                path=path,
                data='{"max_results": 1}' if "search" in path else None,
                headers={"Content-Type": "application/json"} if "search" in path else None,
                allow_redirects=False,
            )
            if not r:
                continue
            data, err = parse_json_response(r) if "search" in path else (None, "skip")
            if not err and data and "experiments" in data:
                self.set_info(severity="medium", reason="MLflow experiments API exposed", path=path)
                return True
            body = (r.text or "").lower()
            if is_html_response(r) and "mlflow" in body and ("experiments" in body or "mlflow" in body):
                self.set_info(severity="medium", reason="MLflow UI detected", path=path)
                return True
        return False
