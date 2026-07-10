#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify exposed Ollama API with model enumeration."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Ollama API Exposure Verification",
        "description": "Confirms Ollama /api/tags and /api/version respond without authentication.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["ollama", "llm", "ai", "scanner", "unauth", "verify"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["ai_panel", "unauth_read"]},
        },
    }

    port = OptPort(11434, "Ollama API port", True)

    def run(self):
        models = []
        version = ""
        r = self.http_request(method="GET", path="/api/tags", allow_redirects=False)
        data, err = parse_json_response(r) if r else (None, "bad_status")
        if not err and isinstance(data, dict):
            for item in data.get("models") or []:
                name = str(item.get("name") or "")
                if name:
                    models.append(name)

        r2 = self.http_request(method="GET", path="/api/version", allow_redirects=False)
        data2, err2 = parse_json_response(r2) if r2 else (None, "bad_status")
        if not err2 and isinstance(data2, dict):
            version = str(data2.get("version") or "")

        if models or version:
            self.set_info(
                severity="high",
                reason="Ollama API exposes models/version without authentication",
                model_count=len(models),
                models=",".join(models[:6]),
                version=version,
                confidence="high",
            )
            return True
        return False
