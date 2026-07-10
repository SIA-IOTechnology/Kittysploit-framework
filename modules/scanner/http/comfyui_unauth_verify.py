#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify ComfyUI unauthenticated workflow API access."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ComfyUI Unauth Verification",
        "description": "Confirms ComfyUI system_stats and object_info APIs without authentication.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["comfyui", "ai", "diffusion", "scanner", "unauth", "verify"],
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

    port = OptPort(8188, "ComfyUI port", True)

    def run(self):
        for path in ("/system_stats", "/object_info"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            data, err = parse_json_response(r) if r else (None, "bad_status")
            if err or not isinstance(data, dict) or not data:
                continue
            self.set_info(
                severity="high",
                reason="ComfyUI API exposes workflow/system data without authentication",
                path=path,
                key_count=len(data),
                confidence="high",
            )
            return True
        return False
