#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify unauthenticated MLflow experiment listing."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "MLflow Unauth Verification",
        "description": "Confirms MLflow experiments search API without authentication.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["mlflow", "ml", "ai", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["ai_panel", "unauth_read"]},
        },
    }

    port = OptPort(5000, "MLflow port", True)

    def run(self):
        r = self.http_request(
            method="POST",
            path="/api/2.0/mlflow/experiments/search",
            data='{"max_results": 5}',
            headers={"Content-Type": "application/json"},
            allow_redirects=False,
        )
        data, err = parse_json_response(r) if r else (None, "bad_status")
        if err or not isinstance(data, dict):
            return False
        experiments = data.get("experiments") or []
        if experiments is not None:
            self.set_info(
                severity="high",
                reason="MLflow experiments API readable without authentication",
                experiment_count=len(experiments),
                confidence="high",
            )
            return True
        return False
