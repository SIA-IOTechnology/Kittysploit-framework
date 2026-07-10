#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fingerprint WAF/CDN products using benign malicious probes."""

from __future__ import annotations

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.waf_fingerprint import fingerprint_waf


class Module(Scanner, Http_client):
    __info__ = {
        "name": "WAF/CDN Fingerprint",
        "description": "Identify WAF or CDN products from response headers and blocking behavior.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "waf", "cdn", "fingerprint", "scanner"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
        },
    }

    path = OptString("/", "Path to probe", required=True)
    output_file = OptString("", "Optional JSON output file", required=False)

    def check(self):
        try:
            return bool(self.http_request(method="GET", path=str(self.path or "/")))
        except Exception:
            return False

    def run(self):
        baseline = self.http_request(method="GET", path=str(self.path or "/"), allow_redirects=False)
        if not baseline:
            print_error("Baseline request failed")
            return False

        malicious_path = f"{self.path}?id=1' OR '1'='1"
        probe = self.http_request(method="GET", path=malicious_path, allow_redirects=False)
        if not probe:
            print_error("Probe request failed")
            return False

        findings = fingerprint_waf(
            baseline.status_code,
            baseline.headers,
            baseline.text or "",
            probe.status_code,
            probe.headers,
            probe.text or "",
        )
        if not findings:
            print_info("No WAF/CDN fingerprint detected")
            return False

        vendors = sorted({f.get("vendor", "") for f in findings if f.get("vendor")})
        self.set_info(
            severity="info",
            reason=f"WAF/CDN signals: {', '.join(vendors)}",
            findings=findings,
        )
        for item in findings[:12]:
            print_info(f"[{item.get('vendor')}] {item.get('detail')} ({item.get('signal')})")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump({"findings": findings}, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return True
