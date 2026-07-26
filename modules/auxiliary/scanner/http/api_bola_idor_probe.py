#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe API endpoints for Broken Object Level Authorization (BOLA/IDOR)."""

from __future__ import annotations

import json
from typing import Dict, List

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.api_idor_probe import compare_idor_responses


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "API BOLA / IDOR Probe",
        "description": (
            "Tests API object endpoints with alternate IDs to detect unauthorized "
            "cross-object access (OWASP API1:2023 BOLA)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["web", "api", "idor", "bola", "scanner", "owasp"],
        "references": [
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 8,
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

    path_template = OptString("/api/users/{id}", "API path with {id} placeholder", required=True)
    baseline_id = OptString("1", "Baseline object identifier", required=True)
    test_ids = OptString("2,3,4,10,100", "Comma-separated alternate IDs", required=False)
    method = OptChoice("GET", "HTTP method", required=True, choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    output_file = OptString("", "Optional JSON output file", required=False)

    def _build_path(self, object_id: str) -> str:
        template = str(self.path_template or "/api/users/{id}")
        return template.replace("{id}", str(object_id).strip())

    def _request(self, path: str):
        method = str(self.method or "GET").upper()
        return self.http_request(method=method, path=path, allow_redirects=False)

    def check(self):
        try:
            return bool(self._request(self._build_path(str(self.baseline_id or "1"))))
        except Exception:
            return False

    def run(self):
        baseline_id = str(self.baseline_id or "1").strip()
        baseline_resp = self._request(self._build_path(baseline_id))
        if not baseline_resp:
            print_error("Baseline request failed")
            return {"error": "baseline_failed"}

        findings: List[Dict[str, str]] = []
        raw_ids = str(self.test_ids or "2,3,4").split(",")
        for alt in raw_ids:
            alt_id = alt.strip()
            if not alt_id or alt_id == baseline_id:
                continue
            resp = self._request(self._build_path(alt_id))
            if not resp:
                continue
            signal = compare_idor_responses(
                baseline_resp.status_code,
                baseline_resp.text or "",
                resp.status_code,
                resp.text or "",
            )
            if not signal:
                continue
            item = {
                "baseline_id": baseline_id,
                "test_id": alt_id,
                "path": self._build_path(alt_id),
                **signal,
            }
            findings.append(item)
            print_warning(f"[{signal.get('severity')}] {item['path']} — {signal.get('description')}")

        data = {"findings": findings, "count": len(findings)}
        if not findings:
            print_info("No BOLA/IDOR signals detected")
        else:
            print_success(f"BOLA/IDOR findings: {len(findings)}")

        if self.output_file:
            try:
                with open(str(self.output_file), "w") as fp:
                    json.dump(data, fp, indent=2)
                print_success(f"Results saved to {self.output_file}")
            except Exception as exc:
                print_error(f"Failed to save output: {exc}")
        return data
