#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Host header and X-Forwarded-Host injection misconfigurations."""

from __future__ import annotations

import json
from typing import Dict, List

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Host Header Injection Probe",
        "description": (
            "Tests Host and X-Forwarded-Host manipulation for reflection in responses, "
            "redirects, and cache/password-reset style poisoning signals."
        ),
        "author": ["KittySploit Team"],
        "tags": ["web", "host-header", "cache-poison", "scanner", "misconfig"],
        "references": [
            "https://portswigger.net/web-security/host-header",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 6,
        'reversible': True,
        'approval_required': False,
        'produces': ['risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'endpoints', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    path = OptString("/", "Path to test", required=True)
    evil_host = OptString("evil.kittysploit.local", "Injected host value", required=False)
    output_file = OptString("", "Optional JSON output file", required=False)

    def _request(self, headers: Dict[str, str]):
        return self.http_request(
            method="GET",
            path=str(self.path or "/"),
            headers=headers,
            allow_redirects=False,
        )

    def _finding(self, vector: str, signal: str, detail: str) -> Dict[str, str]:
        return {"vector": vector, "signal": signal, "detail": detail}

    def _host_reflected(self, body: str, evil: str) -> bool:
        return evil.lower() in (body or "").lower()

    def _redirect_points_to_evil(self, location: str, evil: str) -> bool:
        if not location:
            return False
        return evil.lower() in location.lower()

    def check(self):
        try:
            resp = self.http_request(method="GET", path=str(self.path or "/"))
            return bool(resp)
        except Exception:
            return False

    def run(self):
        evil = str(self.evil_host or "evil.kittysploit.local").strip()
        findings: List[Dict[str, str]] = []

        baseline = self._request({})
        baseline_body = (baseline.text or "") if baseline else ""
        if evil.lower() in baseline_body.lower():
            print_info("Injected host already present in baseline — results may include false positives")

        vectors = {
            "Host": {"Host": evil},
            "X-Forwarded-Host": {"X-Forwarded-Host": evil},
            "X-Host": {"X-Host": evil},
            "X-Forwarded-Server": {"X-Forwarded-Server": evil},
        }

        for vector, headers in vectors.items():
            resp = self._request(headers)
            if not resp:
                continue
            body = resp.text or ""
            location = resp.headers.get("Location", "")
            if self._host_reflected(body, evil):
                findings.append(self._finding(vector, "body_reflection", f"{vector} reflected in response body"))
                print_warning(f"{vector} reflected in body")
            if self._redirect_points_to_evil(location, evil):
                findings.append(self._finding(vector, "redirect_poisoning", f"Location header uses injected host: {location}"))
                print_warning(f"{vector} poisoned redirect: {location}")
            password_reset_markers = ("reset-password", "password-reset", "forgot-password", "recover")
            if any(marker in body.lower() for marker in password_reset_markers) and evil.lower() in body.lower():
                findings.append(self._finding(vector, "password_reset_poisoning", "Injected host appears in password-reset context"))
                print_warning(f"{vector} password-reset poisoning signal")

        data = {"evil_host": evil, "path": str(self.path or "/"), "findings": findings, "count": len(findings)}
        if not findings:
            print_success("No host header injection signals detected")
        else:
            print_warning(f"Host header findings: {len(findings)}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data
