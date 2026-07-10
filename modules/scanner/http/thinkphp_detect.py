#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect ThinkPHP framework fingerprints (safe passive probes)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ThinkPHP Detection",
        "description": "Detects ThinkPHP routing errors and framework markers without exploitation.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "thinkphp", "php", "framework"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    def run(self):
        probes = (
            "/index.php?s=/Index/index",
            "/index.php?s=/captcha",
            "/index.php",
        )
        markers = (
            "thinkphp",
            "think\\exception",
            "module not exists",
            "controller not exists",
            "method not exists",
            "think\\db",
        )
        for path in probes:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 404, 500):
                continue
            body = (r.text or "").lower()
            if is_html_response(r) and not any(marker in body for marker in markers):
                continue
            if any(marker in body for marker in markers):
                self.set_info(severity="info", reason="ThinkPHP framework indicator detected", path=path)
                return True
        return False
